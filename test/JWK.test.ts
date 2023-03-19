
import { JWK } from '../src'

it("can generate JWK for alg", async () => {
  const {publicKey, privateKey} = await JWK.generate('ES256');
  expect(publicKey.alg).toBe('ES256');
  expect(privateKey.alg).toBe('ES256')
})
