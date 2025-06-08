/**
 * Rise is a protocol for decentalized, eclipse-resistant identities. 
 * @module rise
 * @author tactical chihuahua <161chihuahuas@disroot.org>
 * @license LGPL-2.1
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

  /**
   * Default difficuly setting. Require this many leading zeroes in solution 
   * proofs.
   */ 
  static get Z() {
    return 6;
  }

  /**
   * Lowered difficulty for testing.
   */
  static get TEST_Z() {
    return 0;
  }

  /**
   * Equihash N parameter (width in bits).
   */
  static get N() {
    return 102;
  }

  /**
   * Lowered width for testing.
   */
  static get TEST_N() {
    return 90;
  }

  /**
   * Equihash K parameter (length).
   */
  static get K() {
    return 5;
  }

  /**
   * Lowered length for testing.
   */
  static get TEST_K() {
    return 5;
  }

  /**
   * Rise magic number. Used as message terminator and protocol identitifier.
   */
  static get MAGIC() {
    return sha256(Buffer.from('¬«', 'binary'));
  }

  /**
   * Magic number to segment test network.
   */
  static get TEST_MAGIC() {
    return sha256(Buffer.from('¡', 'binary'));
  }

  /**
   * Rise default salt for pbkdf2 operations.
   */
  static get SALT() {
    return Buffer.from('\fæ×"\x94ì9\x82BW(i<ªþ`', 'binary');
  }

  /**
   * Rise *private* identity bundle. This is the primary interface for using 
   * this module. Allows to generate new identities and use them as the 
   * context for protected operations.
   * @constructor
   * @param {Uint8Array|buffer} [entropy] - Private key (secp256k1). If absent
   * a new one will be created.
   * @param {RiseSolution} [solution] - Equihash solution corresponding to the 
   * given private key.
   * @param {Uint8Array|buffer} [salt=RiseSolution~SALT] - Salt used for local 
   * pbkdf2 operations locking/unlocking this identity.
   */
  constructor(entropy, solution, salt = RiseIdentity.SALT) {
    entropy = entropy || secp.utils.randomPrivateKey();

    /** 
     * Used for local PBKDF2.
     * @member {Uint8Array|buffer}
     */ 
    this.salt = salt; 
    /** 
     * BIP39 recovery words. 
     * @member {string}
     */ 
    this.mnemonic = bip39.entropyToMnemonic(entropy);
    /** 
     * Underlying secret key.
     * @member {RiseSecret} 
     */ 
    this.secret = new RiseSecret(entropy);
    /** 
     * Underlying equihash solution.
     * @member {RiseSolution}
     */ 
    this.solution = solution || {};
  }

  /**
   * 160 bit solution hash.
   * @member {buffer}
   */ 
  get fingerprint() {
    return this.solution.fingerprint;
  }

  /**
   * Creates a new {@link RiseSolution} for this identity. This method updates 
   * the internal state and will overwrite any previous solution performed in 
   * this context.
   * @param {number} [n=RiseIdentity.N] - Width in bits.
   * @param {number} [k=RiseIdentity.K] - Solution length.
   * @param {buffer} [epoch=RiseIdentity.MAGIC] - Prepended to public key before 
   * hashing. This can be used to segment protocol versions by changing this value
   * which would render solutions generated with a previous or otherwise different 
   * value invalid and require a new solution.
   * @returns {Promise<RiseSolution>}
   */ 
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

  /**
   * Returns a plain object representation of this identity, serializable to JSON.
   * @returns {object}
   */
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

  /**
   * Creates an encrypted blob representation of this identity, suitable for 
   * persistance to disk.
   * @param {string} password - User provided passphrase used to encrypt this 
   * identity.
   * @returns {buffer}
   */ 
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

  /**
   * Constructs an encrypted and signed {@link RiseMessage} for the given 
   * public key.
   * @param {Uint8Array|buffer} toPublicKey - Recipient identity for encryption.
   * @param {Object.<string, string>} [body] - Key-value pairs to serialize in the 
   * message.
   * @param {Object.<string, string>} [head] - Custom headers to include. **Headers 
   * are NOT ENCRYPTED**. Only information that is necessary for routing should be 
   * included here. 
   * @returns {SignedRiseMessage}
   */ 
  message(toPublicKey, body = {}, head = {}) {
    const clearMsg = new RiseMessage(this.solution, body, head);
    const cryptMsg = clearMsg.encrypt(toPublicKey);
    return cryptMsg.sign(this.secret.privateKey);
  }

  /**
   * Decrypts the blob given the password and creates a new instance.
   * @param {string} password - User supplied passphrase for decryption.
   * @param {buffer} data - Binary blob of encrypted identity.
   * @param {buffer} [salt=RiseIdentity.SALT] - Salt for pbkdf2.
   * @returns {RiseIdentity}
   */ 
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

  /**
   * "Mines" a new {@link RiseIdentity} and *iteratively* generates 
   * {@link RiseSolution}s until one is found that satisfies the stated 
   * difficulty.
   * @param {number} [zeroes=RiseIdentity.Z] - Difficulty level expressed in 
   * number of leading zero bits.
   * @param {number} [n=RiseIdentity.N] - Width in bits.
   * @param {number} [k=RiseIdentity.K] - Solution length.
   * @param {buffer} [epoch=RiseIdentity.MAGIC] - Network magic number.
   * @returns {RiseIdentity}
   */
  static generate(zeroes = RiseIdentity.Z, n, k, epoch) {
    return new Promise(async (resolve, reject) => {
      let id, sol;

      do {
        id = new RiseIdentity();
        try {
          sol = await id.solve(n, k, epoch);
        } catch (e) {
          return reject(e);
        }
      } while (sol.difficulty < zeroes)

      resolve(id);
    });
  }

}


class RiseSecret {

  /**
   * Interface for secp256k1 key pair. If no secret is provided, one will be 
   * generated.
   * @constructor
   * @param {Uint8Array|buffer} [secret] - Private key to use.
   */
  constructor(secret) {
    /** 
     * Underlying private key.
     * @member {Uint8Array} 
     */ 
    this.privateKey = secret
      ? Uint8Array.from(secret)
      : secp.utils.randomPrivateKey();
  }

  /** 
   * Public key derived from private key.
   * @member {Uint8Array}
   */
  get publicKey() {
    return secp.getPublicKey(this.privateKey);
  }

  /**
   * Decrypts the given data using the underlying private key.
   * @param {Uint8Array|buffer} message - Encrypted blob.
   * @returns {Uint8Array}
   */
  decrypt(message) {
    return ecies.decrypt(this.privateKey, message);    
  }

  /**
   * Creates a digital signature from the provided data.
   * @param {Uint8Array|buffer} message - Binary blob to sign.
   * @returns {string} hexSignature
   */
  sign(message) {
    const buf = message;
    const msg = sha256(buf);
    const sig = secp.sign(msg, this.privateKey);

    return sig.toCompactHex();
  }

}


class RiseMessage {

  /**
   * Protocol headers included in every rise message.
   * @typedef {object} RiseMessage~Head
   * @prop {string} nonce - One-time token to prevent replay attacks.
   * @prop {string} version - Version of the rise package. Analagous to user agent.
   * @prop {boolean} ciphertext - Indicates if the message body should be treated 
   * as ciphertext (it is encrypted).
   * @prop {RiseSolution} solution - Sender authentication data.
   */

  /**
   * Interface allowing for authenticated message exchange.
   * @constructor
   * @param {RiseSolution} solution - Identity solution data.
   * @param {Object.<string, string>} [body] - Key-value data to include.
   * @param {Object.<string, string>} [head] - Additional headers.
   */
  constructor(solution, body = {}, headers = {}) {
    /** 
     * Default message headers, plus any custom ones supplied.
     * @member {RiseMessage~Head}
     */
    this.head = {
      nonce: Date.now() + '~' + crypto.randomBytes(8).toString('base64'),
      version: require('./package.json').version,
      ciphertext: false,
      solution,
      ...headers
    };
    /** 
     * Key-value pairs given for the message.
     * @member {Object.<string, string>|string} 
     */
    this.body = Buffer.isBuffer(body)
      ? body.toString('base64')
      : body;
  }

  /**
   * Encrypts the message state for the public key provided.
   * @param {Uint8Array|buffer} publicKey - Recipient public key.
   * @returns {EncryptedRiseMessage}
   */
  encrypt(publicKey) {
    const body = this.head.ciphertext
      ? this.body
      : JSON.stringify(this.body);

    return new EncryptedRiseMessage(this.head.solution,
      ecies.encrypt(publicKey, body), this.head);
  }  

  /**
   * Signs the message state using the private key provided.
   * @param {Uint8Array|buffer} privateKey - Identity to use for signature.
   * @returns {SignedRiseMessage}
   */
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

  /**
   * Returns only the body of this message.
   * @returns {Object.<string, string|RiseMessage|EncryptedRiseMessage|SignedRiseMessage|string>}
   */
  unwrap() {
    return this.body;
  }

  /**
   * Ensures the solution header is valid.
   * @returns {boolean}
   */
  validate() {
    return this.head.solution.verify(...arguments);
  }

  /**
   * Serializes the message to wire format.
   * @returns {buffer}
   */
  toBuffer() {
    const magicStr = RiseIdentity.MAGIC.toString('hex'); 
    const head = JSON.stringify(this.head);
    const body = this.head.ciphertext
      ? this.body
      : JSON.stringify(this.body);
    const str = [head, body].join(magicStr);

    return Buffer.from(str);
  }

  /**
   * Creates a new message instance from the serialized message.
   * @param {buffer} message - Binary blob to deserialize.
   * @returns {RiseMessage|EncryptedRiseMessage|SignedRiseMessage}
   */
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

  /**
   * Interface for an encrypted message.
   * @constructor
   * @extends {RiseMessage}
   */
  constructor() {
    super(...arguments);
    this.head.ciphertext = true;
  }

  /**
   * Decrypts the message using the supplied private key.
   * @param {Uint8Array|buffer} privateKey - Private key to use.
   * @returns {RiseMessage}
   */
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

  /**
   * Interface for digitall signed rise message
   * @constructor
   * @extends {EncryptedRiseMessage}
   */ 
  constructor() {
    super(...arguments);
  }

  /**
   * Ensures that the digita signature is valid.
   * @returns {boolean}
   */
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

  /**
   * Interface for identity solutions.
   * @param {buffer} proof - Equihash proof value.
   * @param {number} nonce - Solution nonce.
   * @param {buffer} pubkey - Public key solution was seeded from.
   * @param {buffer} epoch - Magic network number prepended to public key.
   */
  constructor(proof, nonce, pubkey, epoch = RiseIdentity.MAGIC) {
    /** 
     * Equihash proof.
     * @member {buffer} 
     */
    this.proof = proof;
    /** 
     * Solution nonce.
     * @member {nuber} 
     */
    this.nonce = nonce;
    /** 
     * Network magic number.
     * @member {buffer}
     */
    this.epoch = epoch;
    /** 
     * Public key.
     * @member {buffer}
     */
    this.pubkey = Buffer.from(pubkey);
  }

  /** 
   * RIPEMD-160 hash for SHA-256 hash of serialized solution.
   * @member {buffer}
   */
  get fingerprint() {
    return rmd160(sha256(Buffer.from(JSON.stringify(this.toJSON()))));
  }

  /**
   * Number of leading zeroes in the proof.
   * @member {number}
   */
  get difficulty() {
    const binStr = this.getProofAsBinaryString();
    
    for (let i = 0; i < binStr.length; i++) {
      if (binStr[i] !== '0') {
        return i;
      }
    }

    return binStr.length;
  }

  /**
   * Serilaizes the solution into a JSON object.
   * @returns {Object.<string, string>}
   */ 
  toJSON() {
    return {
      proof: this.proof.toString('base64'),
      nonce: this.nonce.toString(),
      pubkey: this.pubkey.toString('base64'),
      epoch: this.epoch.toString('base64')
    };
  }

  /**
   * Constructs a {@link RiseSolution} from a JSON object.
   * @param {Object.<string, string>} json - Serialized solution.
   * @returns {RiseSolution}
   */
  static fromJSON(json) {
    return new RiseSolution(Buffer.from(json.proof, 'base64'), parseInt(json.nonce),
      Buffer.from(json.pubkey, 'base64'), Buffer.from(json.epoch, 'base64'));
  }

  /**
   * Ensures that the solution is valid.
   * @param {number} [n=RiseIdentity.N] - Width in bits.
   * @param {number} [k=RiseIdentity.K] - Proof length.
   * @returns {Promise<boolean>}
   */
  verify(n = RiseIdentity.N, k = RiseIdentity.K) {
    return equihash.verify(sha256(Buffer.concat([this.epoch, this.pubkey])),
      this.proof, this.nonce, n, k);
  }

  /**
   * Represents the proof as a string of 1's and 0's.
   * @returns {string}
   */ 
  getProofAsBinaryString() {
    const mapping = {
      '0': '0000',
      '1': '0001',
      '2': '0010',
      '3': '0011',
      '4': '0100',
      '5': '0101',
      '6': '0110',
      '7': '0111',
      '8': '1000',
      '9': '1001',
      'a': '1010',
      'b': '1011',
      'c': '1100',
      'd': '1101',
      'e': '1110',
      'f': '1111'
    };
    const hexaString = this.proof.toString('hex').toLowerCase();
    const bitmaps = [];

    for (let i = 0; i < hexaString.length; i++) {
      bitmaps.push(mapping[hexaString[i]]);
    }

    return bitmaps.join('');
  }

}


module.exports.Secret = RiseSecret;
module.exports.Message = RiseMessage;
module.exports.EncryptedMessage = EncryptedRiseMessage;
module.exports.SignedMessage = SignedRiseMessage;
module.exports.Identity = RiseIdentity;
module.exports.Solution = RiseSolution;
