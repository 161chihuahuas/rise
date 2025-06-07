'use strict';

const { expect } = require('chai');
const rise = require('./index.js');


describe('@module rise', function() {

  let i1, i2, i3, i4, i5;
  let m1, m2, m3, m4, m5;
  let l1, u1;

  this.timeout(6000);
 
  describe('@class RiseIdentity', function() {

    it('returns the correct constants', function() {
      expect(rise.Identity.N).to.equal(126);
      expect(rise.Identity.TEST_N).to.equal(90);
      expect(rise.Identity.K).to.equal(5);
      expect(rise.Identity.TEST_K).to.equal(5);
      expect(rise.Identity.MAGIC.toString('base64')).to.equal('m5Q6fK4Y7oqTURB542xE/nMHtQA5zweXGZiFkCAPl6E=');
      expect(rise.Identity.TEST_MAGIC.toString('base64')).to.equal('iolQ92I2YyIlQslGnHO+PEyBu98BnixXdZCmHyzpoVc=');
    });

    it('generates identities from equihash solutions', async function() {
      i1 = await rise.Identity.generate(90, 5);
      i2 = await rise.Identity.generate(90, 5);
      i3 = await rise.Identity.generate(90, 5);
      i4 = await rise.Identity.generate(90, 5);
      i5 = await rise.Identity.generate(90, 5);
      expect(i1).to.be.instanceOf(rise.Identity);
      expect(i2).to.be.instanceOf(rise.Identity);
      expect(i3).to.be.instanceOf(rise.Identity);
      expect(i4).to.be.instanceOf(rise.Identity);
      expect(i5).to.be.instanceOf(rise.Identity);
      expect(await i1.solution.verify(90, 5)).to.equal(true);
      expect(await i2.solution.verify(90, 5)).to.equal(true);
      expect(await i3.solution.verify(90, 5)).to.equal(true);
      expect(await i4.solution.verify(90, 5)).to.equal(true);
      expect(await i5.solution.verify(90, 5)).to.equal(true);
    });

    it('serializes to json', function() {
      const json = i1.toJSON();
      expect(typeof json.secret).to.equal('string');
      expect(typeof json.salt).to.equal('string');
      expect(typeof json.version).to.equal('string');
      expect(typeof json.solution.proof).to.equal('string');
      expect(typeof json.solution.nonce).to.equal('string');
      expect(typeof json.solution.pubkey).to.equal('string');
      expect(typeof json.solution.epoch).to.equal('string');
    });

    it('password encrypts and decrypts the identity', function() {
      l1 = i1.lock('keyboard cat');
      u1 = rise.Identity.unlock('keyboard cat', l1);
      expect(u1).to.be.instanceOf(rise.Identity);
    });

  });

  describe('@class RiseMessage', function() {

    it('encrypts and signs a message', async function() {
      m1 = i1.message(i5.secret.publicKey, {
        from: 'i1',
        to: 'i5'
      });
      expect(m1).to.be.instanceOf(rise.SignedMessage);
      expect(m1.head.ciphertext).to.equal(true);
      expect(m1.head.signature).to.exist;
    });

    it('validates a solution in message header', async function() {
      expect(await m1.validate(90, 5)).to.equal(true);
    });

    it('verifies a message', function() {
      expect(m1.verify()).to.equal(true);
    });

    it('decrypts a message', function() {
      expect(m1.decrypt(i5.secret.privateKey)).to.be.instanceOf(rise.Message);
      expect(m1.decrypt(i5.secret.privateKey).body.from).to.equal('i1');
      expect(m1.decrypt(i5.secret.privateKey).body.to).to.equal('i5');
    });

    it('onion wraps messages successfully', function() {
      m2 = i1.message(i4.secret.publicKey, m1);
      m3 = i1.message(i3.secret.publicKey, m2);
      m4 = i1.message(i2.secret.publicKey, m3);
      m5 = i1.message(i1.secret.publicKey, m4);
      let final = m5.decrypt(i1.secret.privateKey)
        .body.decrypt(i2.secret.privateKey)
        .body.decrypt(i3.secret.privateKey)
        .body.decrypt(i4.secret.privateKey)
        .body.decrypt(i5.secret.privateKey)
        .unwrap();
      expect(final.from).to.equal('i1');
      expect(final.to).to.equal('i5');
    });

    it('reconstructs message instance from a buffer', function() {
      const m1b = m1.toBuffer();
      const m1_2 = rise.Message.fromBuffer(m1b);
      expect(m1_2).to.be.instanceOf(rise.SignedMessage);
    });

  });

  describe('@class RiseSolution', function() {

    it('returns a 20 byte fingerprint', function() {
      expect(i1.fingerprint).to.have.lengthOf(20);
    });

    it('recreates a solution instance from json', function() {
      const json = i1.solution.toJSON();
      const sol1 = rise.Solution.fromJSON(json);
      expect(JSON.stringify(json)).to.equal(JSON.stringify(sol1.toJSON()));
    });

  });

});
