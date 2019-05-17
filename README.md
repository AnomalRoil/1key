# 1key

This is a little POC to showcase in the frame of my `One Key To Rule Them All` talk at [NSec.io].

# Installation

1key has been tested using go1.12+.

You can install it with go get:
```
go get github.com/kudelskisecurity/1key
```
and you'll get a 1key binary in your `$GOBIN` folder.

Or you can `git clone` this repo and then:
```
cd 1key
go get
go build
```
To get a local build.

# Usage

1key is taking a ECDSA SSH key file and deriving child ECDSA keys out of it.
It can either store the child key in the SSH-agent, or output it simply.

To store simply the private child keys in the SSH-agent and quit 1key, use the `-q` flag. Notice you can specify more than 1 derivation code and all the corresponding keys will be generated and stored in your SSH-agent:
```bash
./1key -q -key path/to/ecdsakey test1 test2 test3
```

You can check the keys have been added to your SSH-agent using `ssh-add -l`.
To remove them from your agent use `ssh-add -D` or `./1key -rm`. (Notice that could remove other key that might have been currently in the agent as well, but it won't delete anything permanently, excepted if you had a key in memory in your SSH-agent that had never been persisted. Be careful, but if you "just" use SSH keys that are all in your ~/.ssh folder, then this should never be a problem for you, as these keys are then reloaded by the SSH-agent.)

You can also use 1key to connect directly to ssh, altough this might be a feature that will be removed in the future (it simply "Exec" `ssh` using the arguments you give to the flag `-s`, which is not really a nice way to launch ssh...)

1key also allows one to derive a child key from a public key, allowing the owner of the private key to easily generate the corresponding child private key by simply knowing the randomness used to generate the child key.
To do so simply provide it with the public key as input. Notice you'll need to either share your derivation code and your secret with the person holding the private key, or you'll need to share the derivation integer for it to be used afterwards with the `-r` flag to derive the corresponding private key.

Notice that the master SSH key is never sent to SSH Agent, and that it is not possible to use a randomness equal to 0.

1key requires you to provide it with a "secret" value that will be used to derive a random value r, unless you use the flag -r to specify an integer. To provide the secret you can either use `-secret your-secret`, or set it up in a config.json file. 

## Config file
You can have a config.json file holding the secret you want to use, to avoid displaying it in your terminal.
Notice that it is recommended to use a secret of at least 33 random char.

Example of `config.json` file:
```
{"Secret":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b8565"}
```

# Todo

- Use protected/encrypted memory to store main private key in memory?
- Have the config file in a folder inside of the users' $HOME?

# Details
This tool is based on the fact that scalar multiplication is distributive over elliptic curve addition.

Given a curve, E defined in a finite field Zp and a generator G with (large) prime order n, scalar multiplication
 of a point P with scalar z is defined as the repeated addition of a point along that curve z times. 
We denote it zP = P + ... + P, where P is added z times to itself. The point P = (x, y) lies on the curve E. 

The security of modern ECC depends on the intractability of determining z from Q = zP given known values of Q and P 
if z is large (this is known as the "elliptic curve discrete logarithm problem").

Here we use this fact to generate child keys from a master key by computing the point C = P+rG for P the master public key, G the base point of the curve at hand and r a (deterministically generated) random value. By distributivity, C = P+rG = kG+rG=(k+r)G, so the child private key is simply the original private key k plus the random r.

For more details, please check my talk at NSec 2019 about 1key and its principle.
