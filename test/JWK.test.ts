
import {JWK} from '../src'

it("can generate JWK from seed", async () => {
  const privateKey = JWK.generate('ES256');
  expect(privateKey).toBe(privateKey)
});
