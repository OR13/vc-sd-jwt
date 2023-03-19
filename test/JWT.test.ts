import { JWT } from "../src";

const user_claims = require("../examples/jsonld/user_claims.json")

const fresh = (obj:any) => {
  return JSON.parse(JSON.stringify(obj))
}

const { publicKey, privateKey } = {
  publicKey: {
    kty: "EC",
    x: "gHMlnHTNlSdFvM4_QwCqXZicpLz_IOSPX03qRP6u-U0",
    y: "Q5AmytQ-PrQ3GFtJUBGsPFsZnCgdkc2zgqYFYwkycLg",
    crv: "P-256",
    alg: "ES256",
  },
  privateKey: {
    kty: "EC",
    x: "gHMlnHTNlSdFvM4_QwCqXZicpLz_IOSPX03qRP6u-U0",
    y: "Q5AmytQ-PrQ3GFtJUBGsPFsZnCgdkc2zgqYFYwkycLg",
    crv: "P-256",
    d: "jsr4Z0U6jWe3foNLnKGdUOns99I3oW0SXN_4JozTWyM",
    alg: "ES256",
  },
};

it("should error when user claims contains digest keys", async () => {
  const header = { alg: publicKey.alg };
  const payload = fresh(user_claims)
  payload._sd = [
    "8-N936mMUuXx-Kbf6byQTDOwQoFcoapEvVPbYWiRV5M",
    "qkaVSrXEw2sbbqS5YdtU1HMNAEjMofTH_6DCxDr91LQ",
    "ypFwyXOiHzulGDvpY46Jr1nDRexz35FYfBqJWe7xKqc",
  ];
  return expect((async () => {
    await JWT.sign(payload, {privateKey});
  })()).rejects.toEqual(new Error(JWT.SDJWTHasSDClaimException));
});

it("can sign and verify without holder binding", async () => {
  const combined = await JWT.sign(fresh(user_claims), { issuerPrivateKey: privateKey });
  expect(combined).toBeDefined()
  const derived = await JWT.derive(combined, {
    disclose: { "credentialSubject": { "batchNumber": true } },
  });
  expect(derived).toBeDefined()
  const {protectedHeader, payload} = await JWT.verify(derived, {issuerPublicKey: publicKey})
  expect(protectedHeader.alg).toBe(publicKey.alg)
  expect(payload._sd_alg).toBe('sha-256')
  expect(payload.credentialSubject.batchNumber).toBe('1626382736')
});

it("can sign and verify with holder binding", async () => {
  const combined = await JWT.sign(fresh(user_claims), { issuerPrivateKey: privateKey, holderPublicKey: publicKey });
  expect(combined).toBeDefined()
  const derived = await JWT.derive(combined, { 
    aud: 'urn:verifier:123',
    nonce: 'urn:uuid:3dd995e1-d07f-469e-8f35-176935503da1',
    disclose: { "credentialSubject": { "batchNumber": true } },
    holderPrivateKey: privateKey
  });
  expect(derived).toBeDefined()
  const {protectedHeader, payload} = await JWT.verify(derived, {
    expected_aud: 'urn:verifier:123',
    expected_nonce: 'urn:uuid:3dd995e1-d07f-469e-8f35-176935503da1',
    issuerPublicKey: publicKey
  })
  expect(protectedHeader.alg).toBe(publicKey.alg)
  expect(payload._sd_alg).toBe('sha-256')
  expect(payload.credentialSubject.batchNumber).toBe('1626382736')
});

