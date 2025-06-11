# 🌄 rise ~ *eclipse resistant network identities*

A protocol and implementation of self-issued network identities capable of:

* Resistance to identity attacks ("eclipse", "sybil", "spartatus", and friends).
* End-to-end encrypted message format built-in.
* Enveloped/nested/"onion" routing capabilities.
* Compatibility with bitcoin, ethereum, etc (if you are into that sort of thing) .
* Interoperable with any cryptsystem using secp256k1.

```sh
npm install @yipsec/rise --save
```

## what

"Eclipse attacks" refers to a class of identity-based exploits that 
can emerge in structured networks where nodes are allowed to select their own 
routing key. This can allow a group of malicious nodes to place themselves in 
the routing paths of a target and are thereby able to censor or provoke 
erroneous behavior in a target.

rise employs a memory-hard proof-of-work crypto puzzle that nodes must solve in 
order to establish a network identity. The difficulty of this puzzle is tunable
based on the network architecture and security model of the system utilizing it.
This general approach is detailed in the [S/Kademlia](https://telematics.tm.kit.edu/publications/Files/267/SKademlia_2007.pdf) 
research paper.

## how

rise identity `fingerprint`s (analogous to *nodeID*) are:

```
RMD160 ( SHA256 ( 
    EQUIHASH ( NETWORK_DIFFICULTY, 
        SHA256 ( SECP256K1.PUBLIC_KEY ) 
    ) 
) )
```

When generating a network identity, first a node generates a secp256k1 ESDSA 
key pair. The public key is hashed and used as the input to mine an equihash 
solution. This process repeats until a solution of the network-defined 
difficulty is found. The solution is then hashed with sha256 and a final 
round of ripemd160.

The resulting hash is the node's routing key or "fingerprint". Messages 
exchanged between nodes include the public key, the equihash solution, and 
an ECDSA signature so that messages can be validated, authenticated, and 
end-to-end encrypted. A fingerprint is only valid if it is the hash of a 
verified equihash solution matching the difficulty.

Experiment with difficulty adjustments to what suits the network and threat 
model. The default parameters are **N = 90**, **K = 5**, with a resulting 
solution containing **6 leading zeroes**. 

## using

This reference implementation is written in Javascript - except for the 
Equihash solver and verifier, which is a C++ native add-on. The protocol is 
simple and should be portable to any language. If you port it, I'll list 
it here <3.

### example: generate and save an identity

```js
const { writeFile } = require('node:fs/promises');
const rise = require('@yipsec/rise');
const identity = await rise.Identity.generate();

await writeFile('rise.id', identity.lock('password'));
```

### example: load a saved identity

```js
const { readFile } = require('node:fs/promises');
const rise = require('@yipsec/rise');
const crypted = await readFile('rise.id');
const identity = await rise.Identity.unlock('password', crypted);

console.log(identity.toJSON());
```

Generate the documentation with `npm run generate-docs`.

## copying

anti-copyright 2025 chihuahua.rodeo  
licensed under the gnu lesser general public license 2.1 or later
