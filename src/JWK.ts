import * as jose from 'jose';

export const generate = async (alg: string) => {
    const {publicKey, privateKey} = await jose.generateKeyPair(alg, { extractable: true})
    return { 
        publicKey: {...await jose.exportJWK(publicKey), alg},
        privateKey: {...await jose.exportJWK(privateKey), alg}
    }
}