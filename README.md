# vc-sd-jwt

[![CI](https://github.com/or13/vc-sd-jwt/actions/workflows/ci.yml/badge.svg)](https://github.com/or13/vc-sd-jwt/actions/workflows/ci.yml)
![Branches](./badges/coverage-branches.svg)
![Functions](./badges/coverage-functions.svg)
![Lines](./badges/coverage-lines.svg)
![Statements](./badges/coverage-statements.svg)
![Jest coverage](./badges/coverage-jest%20coverage.svg)

<!-- [![NPM](https://nodei.co/npm/@or13/vc-sd-jwt.png?mini=true)](https://npmjs.org/package/@or13/vc-sd-jwt) -->

🚧 Experimental implementation of sd-jwt for use with W3C Verifiable Credentials. 🔥

Based on:

- https://github.com/oauth-wg/oauth-selective-disclosure-jwt
- https://github.com/christianpaquin/sd-jwt
- https://github.com/chike0905/sd-jwt-ts

## Usage

```sh
npm i @or13/vc-sd-jwt --save
```

```ts
import { JWK, JWT } from "@or13/vc-sd-jwt";
const { publicKey, privateKey } = await JWK.generate("ES256");
const credential = await JWT.sign(
  {
    "@context": [
      "https://www.w3.org/2018/credentials/v1",
      "https://w3id.org/vaccination/v1",
    ],
    type: ["VerifiableCredential", "VaccinationCertificate"],
    issuer: "https://example.com/issuer",
    issuanceDate: "2023-02-09T11:01:59Z",
    expirationDate: "2028-02-08T11:01:59Z",
    name: "COVID-19 Vaccination Certificate",
    description: "COVID-19 Vaccination Certificate",
    credentialSubject: {
      vaccine: {
        type: "Vaccine",
        atcCode: "J07BX03",
        medicinalProductName: "COVID-19 Vaccine Moderna",
        marketingAuthorizationHolder: "Moderna Biotech",
      },
      nextVaccinationDate: "2021-08-16T13:40:12Z",
      countryOfVaccination: "GE",
      dateOfVaccination: "2021-06-23T13:40:12Z",
      order: "3/3",
      recipient: {
        type: "VaccineRecipient",
        gender: "Female",
        birthDate: "1961-08-17",
        givenName: "Marion",
        familyName: "Mustermann",
      },
      type: "VaccinationEvent",
      administeringCentre: "Praxis Sommergarten",
      batchNumber: "1626382736",
      healthProfessional: "883110000015376",
    },
  },
  { 
    issuerPrivateKey: privateKey, // issuer signing key
    holderPublicKey: publicKey    // holder binding key
  }
);

const presentation = await JWT.derive(credential, { 
  aud: 'urn:verifier:123',
  nonce: 'urn:uuid:3dd995e1-d07f-469e-8f35-176935503da1',
  disclose: { "credentialSubject": { "batchNumber": true } },
  holderPrivateKey: privateKey // holder binding key
});

const {protectedHeader, payload} = await JWT.verify(presentation, {
  expected_aud: 'urn:verifier:123',
  expected_nonce: 'urn:uuid:3dd995e1-d07f-469e-8f35-176935503da1',
  issuerPublicKey: publicKey // issuer verification key
})
// payload:
// {
//   "_sd_alg": "sha-256",
//   "cnf": {
//     "jwk": {
//       "kty": "EC",
//       "x": "gHMlnHTNlSdFvM4_QwCqXZicpLz_IOSPX03qRP6u-U0",
//       "y": "Q5AmytQ-PrQ3GFtJUBGsPFsZnCgdkc2zgqYFYwkycLg",
//       "crv": "P-256",
//       "alg": "ES256"
//     }
//   },
//   "credentialSubject": {
//     "batchNumber": "1626382736"
//   }
// }
```

## Develop

```bash
npm i
npm t
npm run lint
npm run build
```
