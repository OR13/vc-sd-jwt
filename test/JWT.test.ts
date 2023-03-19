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
    await JWT.sign(header, payload, privateKey);
  })()).rejects.toEqual(new Error(JWT.SDJWTHasSDClaimException));
});

it("can sign and verify", async () => {
  const header = { alg: publicKey.alg };
  const payload = fresh(user_claims)
  const combined = await JWT.sign(header, payload, privateKey);
  expect(combined).toBeDefined()

  const holder_disclosed_claims: any = { "credentialSubject": { "batchNumber": true } }
  const derived = await JWT.derive(combined, holder_disclosed_claims, {privateKey});
  expect(derived).toBeDefined()

  const verified = await JWT.verify(derived, publicKey)
  expect(verified).toBe(true)
});
