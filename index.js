/**
 *
 * @module rise
 */
'use strict';

const crypto = require('node:crypto');

const bip39 = require('bip39');
const ecies = require('eciesjs');
const { secp256k1: secp } = require('@noble/curves/secp256k1');

const equihash = require('@tacticalchihuahua/equihash');


function _hash(alg, input) {
  return crypto.createHash(alg).update(input).digest();
}

function sha256(input) {
  return _hash('sha256', input);
}

function rmd160(input) {
  return _hash('rmd160', input);
}


class RiseIdentity {

  static get N() {
    return 126;
  }

  static get TEST_N() {
    return 90;
  }

  static get K() {
    return 5;
  }

  static get TEST_K() {
    return 5;
  }

  static get MAGIC() {
    return sha256(Buffer.from('¬«', 'binary'));
  }

  static get TEST_MAGIC() {
    return sha256(Buffer.from('¡', 'binary'));
  }

  static get SALT() {
    return Buffer.from('\fæ×"\x94ì9\x82BW(i<ªþ`', 'binary');
  }

  constructor(entropy, solution, salt = RiseIdentity.SALT) {
    entropy = entropy || secp.utils.randomPrivateKey();

    this.salt = salt; 
    this.mnemonic = bip39.entropyToMnemonic(entropy);
    this.secret = new RiseSecret(entropy);
    this.solution = solution || {};
  }

  get fingerprint() {
    return this.solution.fingerprint;
  }

  solve(n = RiseIdentity.N, k = RiseIdentity.K, epoch = RiseIdentity.MAGIC) {
    return new Promise((resolve, reject) => {
      equihash.solve(sha256(
        Buffer.concat([epoch, this.secret.publicKey])
      ), n, k).then(solution => {
        this.solution = new RiseSolution(solution.proof, solution.nonce, 
          this.secret.publicKey, epoch);
        resolve(this.solution);
      }, reject);
    });
  }

  toJSON() {
    return {
      secret: Buffer.from(this.secret.privateKey).toString('base64'),
      salt: this.salt.toString('base64'),
      version: require('./package.json').version,
      solution: this.solution
        ? this.solution.toJSON()
        : {}
    };
  }

  lock(password) {
    const key = crypto.pbkdf2Sync(password, this.salt, 100000, 32, 'sha512');
    const iv = key.subarray(0, 16);
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    const encryptedData = Buffer.concat([
      cipher.update(JSON.stringify(this.toJSON())), 
      cipher.final()
    ]);
    return encryptedData;
  }

  message(toPublicKey, body = {}, head = {}) {
    const clearMsg = new RiseMessage(this.solution, body, head);
    const cryptMsg = clearMsg.encrypt(toPublicKey);
    return cryptMsg.sign(this.secret.privateKey);
  }

  static unlock(password, data, salt = RiseIdentity.SALT) {
    const key = crypto.pbkdf2Sync(password, salt, 100000, 32, 'sha512');
    const iv = key.subarray(0, 16);
    const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
    const decryptedData = Buffer.concat([
      decipher.update(data), 
      decipher.final()
    ]);
    const json = JSON.parse(decryptedData.toString());

    return new RiseIdentity(
      Buffer.from(json.secret, 'base64'),
      RiseSolution.fromJSON(json.solution),
      Buffer.from(json.salt, 'base64')
    );
  }

  static generate(n, k, epoch) {
    return new Promise((resolve, reject) => {
      const id = new RiseIdentity();

      id.solve(n, k, epoch).then(() => resolve(id), reject);
    });
  }

}

class RiseSecret {

  constructor(secret) {
    this.privateKey = secret
      ? new Uint8Array(secret)
      : secp.utils.randomPrivateKey();
  }

  get publicKey() {
    return secp.getPublicKey(this.privateKey);
  }


  decrypt(message) {
    return ecies.decrypt(this.privateKey, message);    
  }

  sign(message) {
    const buf = message;
    const msg = sha256(buf);
    const sig = secp.sign(msg, this.privateKey);

    return sig.toCompactHex();
  }

}

class RiseMessage {

  constructor(solution, body = {}, headers = {}) {
    this.head = {
      nonce: Date.now() + '~' + crypto.randomBytes(8).toString('base64'),
      version: require('./package.json').version,
      ciphertext: false,
      solution,
      ...headers
    };
    this.body = Buffer.isBuffer(body)
      ? body.toString('base64')
      : body;
  }

  encrypt(publicKey) {
    const body = this.head.ciphertext
      ? this.body
      : JSON.stringify(this.body);

    return new EncryptedRiseMessage(this.head.solution,
      ecies.encrypt(publicKey, body), this.head);
  }  

  sign(privateKey) {
    const secret = new RiseSecret(privateKey);
    const buf = this.toBuffer(); 
    const sig = secret.sign(buf);
    const msg = new SignedRiseMessage(this.head.solution, this.body, {
      ...this.head,
      signature: sig
    });

    return msg;
  }

  unwrap() {
    return this.body;
  }

  validate() {
    return this.head.solution.verify(...arguments);
  }

  toBuffer() {
    const magicStr = RiseIdentity.MAGIC.toString('hex'); 
    const head = JSON.stringify(this.head);
    const body = this.head.ciphertext
      ? this.body
      : JSON.stringify(this.body);
    const str = [head, body].join(magicStr);

    return Buffer.from(str);
  }

  static fromBuffer(buffer) {
    const str = buffer.toString();
    const magicStr = RiseIdentity.MAGIC.toString('hex'); 
    const [rawHead, rawBody] = str.split(magicStr);
    const head = JSON.parse(rawHead);
    const body = head.ciphertext
      ? rawBody
      : JSON.parse(rawBody);

    head.solution = RiseSolution.fromJSON(head.solution);

    if (head.signature && head.ciphertext) {
      return new SignedRiseMessage(head.solution, body, head);
    }
    
    if (head.ciphertext) {
      return new EncryptedRiseMessage(head.solution, body, head);
    }
  
    return new RiseMessage(head.solution, body, head);
  }

}

class EncryptedRiseMessage extends RiseMessage {

  constructor() {
    super(...arguments);
    this.head.ciphertext = true;
  }

  decrypt(privateKey) {
    const secret = new RiseSecret(privateKey);
    let body = JSON.parse(
      Buffer.from(secret.decrypt(Buffer.from(this.body, 'base64')))
        .toString());
   
    if (body.head && body.body) {

      let { proof, nonce, epoch, pubkey } = body.head.solution;
      const sol = new RiseSolution(
        Buffer.from(proof, 'base64'), 
        parseInt(nonce), 
        Buffer.from(pubkey, 'base64'), 
        Buffer.from(epoch, 'base64')
      );

      body.head.solution = sol;

      if (body.head.signature && body.head.ciphertext) {
        body = new SignedRiseMessage(sol, body.body, body.head);
      } else if (body.head.ciphertext) {
        body = new EncryptedRiseMessage(sol, body.body, body.head);
      } else { 
        body = new RiseMessage(sol, body.body, body.head);
      }
    }

    return new RiseMessage(this.head.solution, body, this.head);
  }

}

class SignedRiseMessage extends EncryptedRiseMessage {

  constructor() {
    super(...arguments);
  }

  verify() {
    const sig = this.head.signature;

    delete this.head.signature;

    const buf = this.toBuffer();
    const msg = sha256(buf);
    const pub = this.head.solution.pubkey;
    const result = secp.verify(sig, msg, pub);

    this.head.signature = sig;

    return result;
  }

}

class RiseSolution {

  constructor(proof, nonce, pubkey, epoch = RiseIdentity.MAGIC) {
    this.proof = proof;
    this.nonce = nonce;
    this.epoch = epoch;
    this.pubkey = Buffer.from(pubkey);
  }

  get fingerprint() {
    return rmd160(sha256(Buffer.from(JSON.stringify(this.toJSON()))));
  }

  toJSON() {
    return {
      proof: this.proof.toString('base64'),
      nonce: this.nonce.toString(),
      pubkey: this.pubkey.toString('base64'),
      epoch: this.epoch.toString('base64')
    };
  }

  static fromJSON(json) {
    return new RiseSolution(Buffer.from(json.proof, 'base64'), parseInt(json.nonce),
      Buffer.from(json.pubkey, 'base64'), Buffer.from(json.epoch, 'base64'));
  }

  verify(n = RiseIdentity.N, k = RiseIdentity.K) {
    return equihash.verify(sha256(Buffer.concat([this.epoch, this.pubkey])),
      this.proof, this.nonce, n, k);
  }

}


module.exports.Secret = RiseSecret;
module.exports.Message = RiseMessage;
module.exports.EncryptedMessage = EncryptedRiseMessage;
module.exports.SignedMessage = SignedRiseMessage;
module.exports.Identity = RiseIdentity;
module.exports.Solution = RiseSolution;
