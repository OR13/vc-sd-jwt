
import yaml from 'js-yaml';
import fs   from 'fs';


import { JWT, YML } from "../../src";

const settings = JSON.parse(JSON.stringify(yaml.load(fs.readFileSync('interop/testcases/settings.yml', 'utf8'))));
const user_claims = JSON.parse(fs.readFileSync('interop/testcases/array_data_types/user_claims.json', 'utf8').toString());
const spec = JSON.parse(JSON.stringify(YML.load(fs.readFileSync('interop/testcases/array_data_types/specification.yml', 'utf8'))));
const issuerPrivateKey = settings.key_settings.issuer_key;
issuerPrivateKey.alg = 'ES256'
const issuerPublicKey = {...issuerPrivateKey};
delete issuerPublicKey.d;

it("array_data_types", async () => {
  const combined = await JWT.sign(user_claims, {
    algorithm: issuerPrivateKey.alg,
    issuer:  settings.identifiers.issuer,
    validFrom: settings.iat,
    validUntil: settings.exp,
    issuerPrivateKey 
  });

  console.log({combined})
  const derived = await JWT.derive(combined, {
    disclose: spec.holder_disclosed_claims,
  });
  const {protectedHeader, payload} = await JWT.verify(derived, { issuerPublicKey })
  expect(protectedHeader.alg).toBe(issuerPrivateKey.alg);
  expect(protectedHeader.typ).toBe(undefined);
  expect(payload._sd_alg).toBe('sha-256');
  console.log(JSON.stringify(payload.data_types, null, 2))
  expect(payload.data_types).toEqual(user_claims.data_types)
});
