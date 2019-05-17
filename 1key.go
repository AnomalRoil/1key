package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"os"
	"os/exec"
	"strings"
	"syscall"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/terminal"
)

// Config is holding the secret value one can set in the config.json file, or using the -secret flag.
type Config struct {
	// This secret is used as HMAC key, so ideally it should be a random string
	// of size bigger than 32 char so that it gets hashed
	Secret string `json:"secret"`
}

// ChildKey is used to store child keys.
type ChildKey struct {
	sk interface{}
	pk ssh.PublicKey
	// cc can be used to store the derivation code used (chain code in BIP32)
	cc string
	// r can be used to store the derivation integer used
	r *big.Int
	// parent is the parent public key
	parent ssh.PublicKey
}

// global config
var (
	config          Config
	armor           *bool
	inputKeyPath    *string
	sshArg          *string
	givenRand       *string
	overrideSecret  *string
	populateAndWait *bool
	populateAndQuit *bool
	removeAll       *bool
	invert          *bool
)

// Logger
var (
	Info    *log.Logger
	Warning *log.Logger
	Error   *log.Logger
)

func loadConf(file string) {
	confFile, err := os.Open(file)
	if err != nil {
		Error.Fatalln("Unable to load config file.\n Consider using the flag -secret to provide a secret value, or create a config.json file containing your secret value.\nError:", err)
	}
	defer func() {
		if err := confFile.Close(); err != nil {
			Error.Fatalln("problem closing the config file:", err)
		}
	}()

	// we load the config into the global config
	err = json.NewDecoder(confFile).Decode(&config)
	if err != nil {
		Error.Fatalln("Unable to parse config file. Error:", err)
	}
}

func init() {
	// We output all text on Stderr so that it is easy to use pipe with 1key
	Info = log.New(os.Stderr, "", 0)
	Warning = log.New(os.Stderr, "Warning:", 0)
	Error = log.New(os.Stderr, "Error:", log.LstdFlags)

	// Let us tweak the usage message:
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage of %s [-key path] [OPTION] [derivation-code]:\n", os.Args[0])
		flag.PrintDefaults()
	}

	// Getting the flag data
	inputKeyPath = flag.String("key", "", "Provide the `path` to the SSH master key you want to use")
	sshArg = flag.String("s", "", "Tells 1key to proceed with SSH connection using these `arguments` for ssh")
	givenRand = flag.String("r", "", "In case you want to use a specific `hexadecimal integer` to derive the key. Must be in hex format.")
	armor = flag.Bool("a", false, "If set, will output the key in PEM encoding, and redirect output to stderr except for the key")
	overrideSecret = flag.String("secret", "", "Allows to override the secret set in config.json")
	populateAndWait = flag.Bool("w", false, "Tells 1key to register the child key in the SSH agent, and then to wait. This notably allows the usage of scp, ssh and other tools relying on ssh-agent just like if the private key file was in ~/.ssh/")
	populateAndQuit = flag.Bool("q", false, "Tells 1key to register the child key in the SSH agent, and then to exit. This allows the same things as -w. The child key will stay in the ssh-agent until it is reinitialized. Allows to register multiple child keys in ssh-agent")
	removeAll = flag.Bool("rm", false, "Cleans out all the keys contained in the SSH agent. Might remove keys coming from other software. Be careful. This won't delete anything on disk.")
	invert = flag.Bool("i", false, "Recovers a master key from a child key using the given randomness. Require -r.")
	flag.Parse()

	if *overrideSecret != "" || *removeAll {
		config.Secret = *overrideSecret
	} else {
		loadConf("config.json")
	}

}

func main() {
	derivationCodes := flag.Args()

	// in the case where we are running with -rm flag, we just remove everything from the ssh-agent
	if *removeAll {
		age := setupSSH()
		unlistAll(age)
		return
	}

	// to use invert we need the random to be given, since we hmac the public key to generate it.
	if *invert && *givenRand == "" {
		flag.Usage()
		Info.Println("")
		Error.Fatalln("To use the invert flag, you need to specify the value of r using -r.")
	}

	// Notice this won't handle double spaces well, since the Exec packages hate them
	sshArgs := strings.Split((*sshArg), " ")

	// we want to quit if we won't have a derivation code, unless it's provided using -r
	if len(derivationCodes) == 0 {
		if *givenRand == "" {
			flag.Usage()
			Info.Println("")
			Error.Fatalln("Missing a derivation code")
		}
		derivationCodes = append(derivationCodes, "")
	}

	if *inputKeyPath == "" {
		Error.Fatalln("No master key specified. Please specify a SSH private key file using the -key flag.")
	}

	Info.Println("Attempting to derive key from", *inputKeyPath, "using the secret you set")

	// Reading the master key file
	kData, err := ioutil.ReadFile(*inputKeyPath)
	if err != nil {
		Error.Fatalf("Unable to read the given file '%v'. Error:\n\t%v\n", *inputKeyPath, err)
	}

	// Parsing the key data
	var masterKey interface{}
	masterKey = parseKey(kData)
	pubMaster := getPub(masterKey)

	var childs []ChildKey
	switch v := masterKey.(type) {
	case *ecdsa.PrivateKey:
		Info.Println("Processing ECDSA master key on curve", v.Curve.Params().Name)
		for _, derCode := range derivationCodes {
			// get randomness deterministically
			r := getDetRand([]byte(derCode), pubMaster, v.Curve.Params().N)
			c := derivePrivECDSA(v, r, *invert)
			c.cc = derCode
			c.parent = pubMaster
			childs = append(childs, c)
		}
	case ssh.CryptoPublicKey:
		var tmpKey interface{}
		tmpKey = v.CryptoPublicKey()
		switch k := tmpKey.(type) {
		case *ecdsa.PublicKey:
			Info.Println("Processing ECDSA public key on curve", k.Curve.Params().Name)
			for _, derCode := range derivationCodes {
				// get randomness deterministically
				r := getDetRand([]byte(derCode), pubMaster, k.Curve.Params().N)
				c := derivePubECDSA(k, r, *invert)
				c.cc = derCode
				c.parent = pubMaster
				childs = append(childs, c)
			}
		default:
			Error.Fatalf("Keys of type %T are not supported. Please re-try using an ECDSA key.\n", k)
		}
	default:
		Error.Fatalf("Keys of type %T are not supported. Please use ECDSA keys.\n", v)
	}

	for _, child := range childs {
		if *armor {
			// if -a we print on stderr to avoid it get piped with the secret key
			Info.Println("Your public child key ", child.cc, " is:")
			Info.Printf(strings.TrimSpace(string(ssh.MarshalAuthorizedKey(child.pk))))
			printKey(child.sk)
		} else {
			// otherwise we print it so that it can be piped
			Info.Println("Your public child key (on stdout) ", child.cc, " is:")
			fmt.Print(strings.TrimSpace(string(ssh.MarshalAuthorizedKey(child.pk))))
		}
		Info.Println("")
	}

	// if we got the ssh flag, we need to proceed with ssh connection.
	if *sshArg != "" && len(childs) == 1 {
		// let's connect to the SSH agent
		age := setupSSH()
		// add our childkey to the SSH agent and not forget to remove it once we're done.
		registerSSHkey(age, childs[0].sk, childs[0].cc)
		defer unlistSSH(age, childs[0].pk)

		// we can list the ssh keys and see it's inside:

		wait(fmt.Sprint("and run `ssh` with the args you provided:", sshArgs))

		// Using the exec package, because it's the easiest way. Notice that
		// this will probably fail if there are spaces in the ssh arguments
		// we passed to 1key, especially if there are quoted cmd to be passed
		// to ssh. This might happen easily if trying to run remote commands
		// on the server using a oneliner. Ideally 1key should only manage
		// adding the proper keys to the SSH agent, but it is not easy to
		// hijack outgoing SSH connections to add the right key just before
		// whenever a user connects. Also for demo purposes this works well.
		cmd := exec.Command("ssh", sshArgs...)
		// we need to redirect all required fd
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		// and we run ssh, hopefully it's installed on the machine running this.
		if err := cmd.Run(); err != nil {
			Info.Println(err)
		}
	} else if *populateAndWait {

		// let's connect to the SSH agent
		age := setupSSH()
		// add our childkey to the SSH agent and not forget to remove it once we're done.
		for _, child := range childs {
			registerSSHkey(age, child.sk, child.cc)
			defer unlistSSH(age, child.pk)
		}
		Info.Println("The following keys are now in the SSH agent:")
		listSSHkeys(age)
		wait("and remove the child key from ssh-agent before quitting.")
	} else if *populateAndQuit {
		// let's connect to the SSH agent
		age := setupSSH()
		// add our childkey to the SSH agent and not forget to remove it once we're done.
		for _, child := range childs {
			registerSSHkey(age, child.sk, child.cc)
		}
		Info.Println("The following keys are now in the SSH agent:")
		listSSHkeys(age)
	}
}

func wait(s string) {
	Info.Println("Press 'Enter' to continue", s)
	_, err := bufio.NewReader(os.Stdin).ReadBytes('\n')
	if err != nil {
		Error.Fatal(err)
	}
}

func requirePass(pemBytes []byte) bool {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		Warning.Println("No private key found")
		return false
	}

	return strings.Contains(block.Headers["Proc-Type"], "ENCRYPTED")
}

func parseKey(keyData []byte) interface{} {
	var pass []byte
	if requirePass(keyData) {
		Info.Println("The key appears to be encrypted and requires a passphrase. Please enter it below:")
		var err error
		pass, err = terminal.ReadPassword(int(syscall.Stdin))
		if err != nil {
			Error.Fatalf("Unable to read the passphrase. Error:\n\t%v\n", err)
		}
	}
	key, err := ssh.ParseRawPrivateKeyWithPassphrase(keyData, pass)
	if err != nil {
		Info.Println("This does not seem to be a private key, attempting to parse it as a public key.")
		key, _, _, _, err = ssh.ParseAuthorizedKey(keyData)
		if err != nil {
			Error.Fatalf("Unable to parse the key. Error:\n\t%v\n", err)
		}
	}
	return key
}

func getDetRand(derivation []byte, par interface{}, order *big.Int) *big.Int {
	ret, zero := new(big.Int), new(big.Int)
	if r := *givenRand; r != "" {
		// let's parse the argument as a hex integer
		_, ok := ret.SetString(r, 16)
		if !ok {
			Error.Fatalln("Unable to parse the given randomness as a hexadecimal integer.")
		}
	}
	// to avoid a modulo bias we rejects values lower than order
	for i := uint64(0); ret.Cmp(order) != -1 || ret.Cmp(zero) == 0; i++ {
		// We want a deterministic value indistinguishable from random.
		// We use the config.Secret as a HMAC key. Notice if it is too short
		// HMAC will left-pad it with zeroes and if it's too big, it hashes it.
		// I.e. the config.Secret corresponds to the "Bitcoin seed" in BIP-32.
		hmac := hmac.New(sha256.New, []byte(config.Secret))
		switch k := par.(type) {
		case ssh.PublicKey:
			// we currently only support non-hardened keys
			hmac.Write(k.Marshal())
		default:
			Error.Fatalf("Currently only non-hardened keys can be derived. %T is not supported.\n", k)
		}
		hmac.Write(derivation)
		buf := make([]byte, binary.MaxVarintLen64)
		binary.PutUvarint(buf, i)
		// we use HMAC(parent pub key | derivation code | i)
		hmac.Write(buf)
		hashed := hmac.Sum(nil)

		ret = new(big.Int).SetBytes(hashed)
	}
	Info.Println("The derivation integer used for", string(derivation), "was:", ret.Text(16))
	return ret
}

// derivePrivECDSA takes a private key and uses the global devName and secret
// variables to derive a new child key.
func derivePrivECDSA(mKey *ecdsa.PrivateKey, detRand *big.Int, inv bool) ChildKey {
	c := mKey.Curve

	//init
	childKey := new(ecdsa.PrivateKey)
	childKey.Curve = c
	// Notice we have to work with N, the order of the base point
	order := c.Params().N

	if inv {
		// in the "invert" case, we need to substract the value instead
		childKey.D = new(big.Int).Mod(new(big.Int).Sub(mKey.D, detRand), order)
	} else {
		// we compute the child secret key d+r
		childKey.D = new(big.Int).Mod(new(big.Int).Add(mKey.D, detRand), order)
	}
	childKey.X, childKey.Y = c.ScalarBaseMult(childKey.D.Bytes())

	if !childKey.Curve.IsOnCurve(childKey.X, childKey.Y) {
		Error.Fatal("Child public key is not on the curve, this should never happen!")
	}

	pub := getPub(childKey.Public())

	return ChildKey{sk: childKey, pk: pub, r: detRand}
}

func getPub(key interface{}) ssh.PublicKey {
	switch k := key.(type) {
	case *ssh.PublicKey:
		return *k
	case *ecdsa.PrivateKey:
		key = k.Public()
	case ssh.CryptoPublicKey:
		var tmpKey interface{}
		tmpKey = k.CryptoPublicKey()
		switch v := tmpKey.(type) {
		case *ecdsa.PublicKey:
			return getPub(v)

		}
	}

	pKey, err := ssh.NewPublicKey(key)
	if err != nil {
		Error.Fatalln("Error getting the corresponding ssh public key. Error:\n", err)
	}

	return pKey
}

func printKey(key interface{}) {
	if key == nil {
		return
	}
	switch k := key.(type) {
	case *ecdsa.PrivateKey:
		encoded, _ := x509.MarshalECPrivateKey(k)
		var pemData []byte
		Info.Println("Please type a passphrase to encrypt your private key, or simply press enter to be insecure")
		bPass, err := terminal.ReadPassword(int(syscall.Stdin))
		if err != nil {
			Error.Fatalf("Unable to read the passphrase. Error:\n\t%v\n", err)
		}
		pass := strings.TrimSpace(string(bPass))
		if pass == "" {
			Warning.Println("The private key is not encrypted!")
			pemData = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: encoded})
		} else {
			encData, err := x509.EncryptPEMBlock(rand.Reader, "EC PRIVATE KEY", encoded, []byte(pass), x509.PEMCipherAES128)
			if err != nil {
				Error.Fatalln("Unable to encrypt the DER encoded private key")
			}
			pemData = pem.EncodeToMemory(encData)

		}
		Info.Println("Your private key is:")
		// we output it on Stdout to ease the pipe into a file
		fmt.Print(string(pemData))
	default:
		Warning.Printf("Unsupported key type %T.\n", k)
	}
}

// derivePubECDSA allows to derive a childkey out of a ecdsa PublicKey, in a
// way that is compatible with
func derivePubECDSA(pKey *ecdsa.PublicKey, detRand *big.Int, inv bool) ChildKey {
	c := pKey.Curve

	rG := new(struct {
		X *big.Int
		Y *big.Int
	})

	childKey := new(ecdsa.PublicKey)
	childKey.Curve = c

	// we compute the point rG
	rG.X, rG.Y = c.ScalarBaseMult(detRand.Bytes())
	if inv {
		// in the "invert" case, we need to substract the value instead.
		// we work in finite field Zp, and tu substract a point (x,y) we need
		// to add the point (x,-y) instead
		rG.Y.Sub(c.Params().P, rG.Y)
	}
	// we have that the pKey is P=dG and we have rG and we compute P') = (d+r)G = P+rG
	childKey.X, childKey.Y = c.Add(pKey.X, pKey.Y, rG.X, rG.Y)

	if !childKey.Curve.IsOnCurve(childKey.X, childKey.Y) {
		Error.Fatal("Child public key is not on the curve, this should never happen!")
	}

	return ChildKey{sk: nil, pk: getPub(childKey), r: detRand}
}

// setupSSH is an helper function to connect to the SSH_AUTH_SOCK socket in order
// to connect to the SSH Agent. It is currently only compatible with Unix sockets.
func setupSSH() agent.ExtendedAgent {
	socket := os.Getenv("SSH_AUTH_SOCK")
	conn, err := net.Dial("unix", socket)
	if err != nil {
		Error.Fatalf("Error connecting to the agent net.Dial: %v.\n Note that only Unix ssh-agent is supported.", err)
	}
	agentC := agent.NewClient(conn)

	return agentC
}

// listSSHkeys is just an helper function to easily list the SSH keys currently in the SSH agent
func listSSHkeys(age agent.ExtendedAgent) {
	listKeys, err := age.List()
	if err != nil {
		Error.Fatalln("Failed to list keys:", err)
	}

	Info.Println("Keys currently in SSH agent:")
	for _, i := range listKeys {
		Info.Println("> ", i)
	}
}

// registerSSHkey adds a private-public keypair to the SSH Agent, allowing it
// to be used just like if the private key was stored in the .ssh folder.
// TODO: find out a way to use it every time we call the ssh agent SSH instead?
// Ideally we would like to generate new child keys on the fly.
func registerSSHkey(age agent.ExtendedAgent, privKey interface{}, cc string) {
	err := age.Add(agent.AddedKey{PrivateKey: privKey, Comment: "ChildKey " + cc})
	if err != nil {
		Error.Fatalln("Failed to add the key to the SSH agent:", err)
	}
}

// unlistSSH removes the key corresponding to the public key it gets in args
// from the SSH agent, to clean up after having added a childkey.
func unlistSSH(age agent.ExtendedAgent, pub ssh.PublicKey) {
	// At the end we remove the child key from SSH Agent.
	if err := age.Remove(pub); err != nil {
		Error.Fatalln("Error removing the key from the ssh agent:", err)
	}

	Info.Println("Everything went well, we removed the child key from SSH agent. Good bye!")
}

// unlistAll removes all keys in the ssh-agent.
func unlistAll(age agent.ExtendedAgent) {
	// At the end we remove the child key from SSH Agent.
	if err := age.RemoveAll(); err != nil {
		Error.Fatalln("Error removing all keys from the ssh agent:", err)
	}

	Info.Println("Everything went well, we removed all keys from the SSH agent. Good bye!")
}
