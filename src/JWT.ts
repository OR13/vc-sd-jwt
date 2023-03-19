import crypto from "crypto";
import * as jose from "jose";
import moment from 'moment';

const DEFAULT_SIGNING_ALG = "ES256";
const SD_DIGESTS_KEY = "_sd";
const DIGEST_ALG_KEY = "_sd_alg";
const COMBINED_FORMAT_SEPARATOR = "~"

export const SDJWTHasSDClaimException =
  "Exception raised when input data contains the special _sd claim reserved for SD-JWT internal data.";

const HASH = {
  ['sha-256']: (raw: string) => {
    return crypto.createHash("sha256").update(raw);
  },
};

// https://github.com/oauth-wg/oauth-selective-disclosure-jwt/blob/master/sd_jwt/operations.py#L89
const _check_for_sd_claim = (user_claims: any) => {
  function replacer(key: string, value: any) {
    if (key === SD_DIGESTS_KEY) {
      throw new Error(SDJWTHasSDClaimException);
    }
    return value;
  }
  JSON.stringify(user_claims, replacer, 2);
};

// https://github.com/oauth-wg/oauth-selective-disclosure-jwt/blob/7aa6f926bfc684eae530ebf1210d74b636ae0a06/sd_jwt/operations.py#L55
const _generate_salt = () => {
  return jose.base64url.encode(crypto.randomBytes(16));
};

const _b64hash = (raw: string) => {
  return jose.base64url.encode(HASH["sha-256"](raw).digest());
};

const _hash_claim = (key: string, value: any, _debug_ii_disclosures_contents: any[]) => {
  const salt = _generate_salt();
  const json = JSON.stringify([salt, key, value]);
  _debug_ii_disclosures_contents.push(JSON.parse(json))
  const raw_b64 = jose.base64url.encode(json);
  const hash = _b64hash(raw_b64);
  return [hash, raw_b64];
};

const _create_sd_claim_entry = (key: string, value: any, ii_disclosures: any[], _debug_ii_disclosures_contents: any[]): string => {
  const [hash, raw_b64] = _hash_claim(key, value, _debug_ii_disclosures_contents);
  ii_disclosures.push(raw_b64)
  return hash;
};

// https://github.com/oauth-wg/oauth-selective-disclosure-jwt/blob/7aa6f926bfc684eae530ebf1210d74b636ae0a06/sd_jwt/operations.py#L167
const _create_sd_claims = (user_claims: any, ii_disclosures: any[], _debug_ii_disclosures_contents:any): any => {
  if (Array.isArray(user_claims)) {
    return user_claims.map((item: any) => {
      return _create_sd_claims(item, ii_disclosures, _debug_ii_disclosures_contents);
    });
  } else if (typeof user_claims === "object") {
    const sd_claims: any = { [SD_DIGESTS_KEY]: [] };
    for (const [key, value] of Object.entries(user_claims)) {
      const subtree_from_here = _create_sd_claims(value, ii_disclosures, _debug_ii_disclosures_contents);
      if (typeof key === "string") {
        sd_claims[SD_DIGESTS_KEY].push(
          _create_sd_claim_entry(key, subtree_from_here, ii_disclosures, _debug_ii_disclosures_contents)
        );
      } else {
        sd_claims[key] = subtree_from_here;
      }
    }
    // TODO: add decoys..
    if (sd_claims[SD_DIGESTS_KEY].length === 0) {
      delete sd_claims[SD_DIGESTS_KEY];
    } else {
      sd_claims[SD_DIGESTS_KEY].sort();
    }
    return sd_claims;
  } else {
    return user_claims;
  }
};

// https://github.com/oauth-wg/oauth-selective-disclosure-jwt/blob/7aa6f926bfc684eae530ebf1210d74b636ae0a06/sd_jwt/operations.py#L137
const _assemble_sd_jwt_payload = (user_claims: any, ii_disclosures: any[], _debug_ii_disclosures_contents: any[], holderPublicKey?: any) => {
  const sd_jwt_payload = _create_sd_claims(user_claims, ii_disclosures, _debug_ii_disclosures_contents);
  sd_jwt_payload[DIGEST_ALG_KEY] = 'sha-256';
  if (holderPublicKey){
    sd_jwt_payload['cnf'] = { jwk: holderPublicKey };
  }
  return sd_jwt_payload;
};

// https://github.com/oauth-wg/oauth-selective-disclosure-jwt/blob/7aa6f926bfc684eae530ebf1210d74b636ae0a06/sd_jwt/operations.py#L215
const _create_signed_jwt = async (header: any, sd_jwt_payload: any, privateKey: any )=>{
  const _headers = { ...header, alg: privateKey.alg };
  _headers.typ = 'sd+jwt';
  const jws = await new jose.CompactSign(
    new TextEncoder().encode(JSON.stringify(sd_jwt_payload)),
  )
    .setProtectedHeader(_headers)
    .sign(await jose.importJWK(privateKey))
  return jws;
}

// https://github.com/oauth-wg/oauth-selective-disclosure-jwt/blob/7aa6f926bfc684eae530ebf1210d74b636ae0a06/sd_jwt/operations.py#L43
const _combine = (...parts: string[]) =>{
  return parts.join(COMBINED_FORMAT_SEPARATOR)
}

// https://github.com/oauth-wg/oauth-selective-disclosure-jwt/blob/7aa6f926bfc684eae530ebf1210d74b636ae0a06/sd_jwt/operations.py#L232
const _create_combined = (serialized_sd_jwt: string, ii_disclosures: any[]) => {
  return _combine(serialized_sd_jwt, ...ii_disclosures)
}

// https://github.com/oauth-wg/oauth-selective-disclosure-jwt/blob/7aa6f926bfc684eae530ebf1210d74b636ae0a06/sd_jwt/operations.py#L105
export const sign = async (header: any, user_claims: any, { issuerPrivateKey, holderPublicKey }: any) => {
  _check_for_sd_claim(user_claims);

  const ii_disclosures:any[] = [];
  const _debug_ii_disclosures_contents:any[] = [];
  
  const sd_jwt_payload = _assemble_sd_jwt_payload(user_claims, ii_disclosures, _debug_ii_disclosures_contents, holderPublicKey);
  const serialized_sd_jwt = await _create_signed_jwt(header, sd_jwt_payload, issuerPrivateKey);
  const combined = _create_combined(serialized_sd_jwt, ii_disclosures)
  return combined;
};

// https://github.com/oauth-wg/oauth-selective-disclosure-jwt/blob/7aa6f926bfc684eae530ebf1210d74b636ae0a06/sd_jwt/operations.py#L46
const _split = (combined: string) => {
  return combined.split(COMBINED_FORMAT_SEPARATOR)
}

// https://github.com/oauth-wg/oauth-selective-disclosure-jwt/blob/7aa6f926bfc684eae530ebf1210d74b636ae0a06/sd_jwt/operations.py#L254
const _parse_combined_sd_jwt_iid = (sd_jwt_combined: string): any[] => {
  const [ serialized_sd_jwt, ..._ii_disclosures] = _split(sd_jwt_combined);
  return [serialized_sd_jwt, _ii_disclosures]
}

// https://github.com/oauth-wg/oauth-selective-disclosure-jwt/blob/7aa6f926bfc684eae530ebf1210d74b636ae0a06/sd_jwt/operations.py#L69
const _create_hash_mappings = (disclosurses_list: string[]) => {
  // Mapping from hash of disclosure to the decoded disclosure
  const _hash_to_decoded_disclosure:any = {}

  // Mapping from hash of disclosure to the raw disclosure
  const _hash_to_disclosure:any = {}

  for (const disclosure of disclosurses_list){
    let decoded_disclosure;
    try{
      const decoded = jose.base64url.decode(disclosure).toString()
      // console.log(decoded)
      decoded_disclosure = JSON.parse(decoded)
    } catch(e){
      throw e;
    }
    
    
    const hash = _b64hash(disclosure);
    if (_hash_to_decoded_disclosure[hash] !== undefined){
      throw new Error(`Duplicate disclosure hash ${hash} for disclosure ${decoded_disclosure}`)
    }
    _hash_to_decoded_disclosure[hash] = decoded_disclosure;
    _hash_to_disclosure[hash] = disclosure
  }
  return {_hash_to_decoded_disclosure, _hash_to_disclosure};

}

const _extract_payload_unverified = (serialized_sd_jwt: string) =>{
  // # TODO: This holder does not verify the SD-JWT yet - this
  // # is not strictly needed, but it would be nice to have.

  // # Extract only the body from SD-JWT without verifying the signature
  const [_header, _jwt_body, ...rest] = serialized_sd_jwt.split('.');
  return JSON.parse(jose.base64url.decode(_jwt_body).toString())
}

const _select_disclosures = (sd_jwt_claims: any, claims_to_disclose: any[], _hash_to_decoded_disclosure: any, _hash_to_disclosure: any, hs_disclosures: any): any => {
  // # Recursively process the claims in sd_jwt_claims. In each
  // # object found therein, look at the SD_DIGESTS_KEY. If it
  // # contains hash digests for claims that should be disclosed,
  // # then add the corresponding disclosures to the claims_to_disclose.

  if (Array.isArray(sd_jwt_claims)){
    let reference: any;
    if (!Array.isArray(claims_to_disclose) || claims_to_disclose.length < 1){
      reference = {}
    } else {
      reference = claims_to_disclose[0]
    }
    return sd_jwt_claims.map((claim: any)=> { return _select_disclosures(claim, reference, _hash_to_decoded_disclosure, _hash_to_disclosure, hs_disclosures) })
  } else if (typeof sd_jwt_claims === 'object'){
    for (const [key, value] of Object.entries(sd_jwt_claims)) {
      if (key === SD_DIGESTS_KEY){
        for (const digest of (value as any)){
          if (_hash_to_decoded_disclosure[digest] === undefined){
            // # fake digest
            continue
          }
          const decoded = _hash_to_decoded_disclosure[digest];
          const [_salt, key, value] = decoded;
          try {
            if (claims_to_disclose[key]){
              hs_disclosures.push(
                _hash_to_disclosure[digest]
              )
            }
          } catch(e){
            // # claims_to_disclose is not a dict
            console.warn(`Check claims_to_disclose for key: ${key}, value: ${value}`)
            throw new Error(`claims_to_disclose does not contain a dict where a dict was expected (found ${claims_to_disclose} instead)`)
          }
          _select_disclosures(value, claims_to_disclose[key as any] || {}, _hash_to_decoded_disclosure, _hash_to_disclosure, hs_disclosures)
        }
      } else {
        _select_disclosures(value, claims_to_disclose[key as any] || {}, _hash_to_decoded_disclosure, _hash_to_disclosure, hs_disclosures)
      }
    }
  } else {
    // pass
  }
}

// https://github.com/oauth-wg/oauth-selective-disclosure-jwt/blob/7aa6f926bfc684eae530ebf1210d74b636ae0a06/sd_jwt/operations.py#L329
const _create_holder_binding_jwt = async (nonce: any, aud: any, privateKey: any) => {
  const header = { alg: privateKey.alg };
  const payload = {
    "nonce": nonce,
    "aud": aud,
    "iat": moment().unix()
  }
  const jws = await new jose.CompactSign(
    new TextEncoder().encode(JSON.stringify(payload)),
  )
    .setProtectedHeader(header)
    .sign(await jose.importJWK(privateKey))
  return jws;
}

// a mixture of the class constructor and create_presentation
// https://github.com/oauth-wg/oauth-selective-disclosure-jwt/blob/7aa6f926bfc684eae530ebf1210d74b636ae0a06/sd_jwt/operations.py#L265
export const derive = async (sd_jwt_combined: string, claims_to_disclose: any[], options?: any) => {
  const [serialized_sd_jwt, _ii_disclosures] = _parse_combined_sd_jwt_iid(sd_jwt_combined)
  const {_hash_to_decoded_disclosure, _hash_to_disclosure} = _create_hash_mappings(_ii_disclosures)
  const sd_jwt_payload = _extract_payload_unverified(serialized_sd_jwt)
  const hs_disclosures:any = []
  _select_disclosures(sd_jwt_payload, claims_to_disclose, _hash_to_decoded_disclosure, _hash_to_disclosure, hs_disclosures)
  let serialized_holder_binding_jwt: any = undefined;
  if (sd_jwt_payload.cnf && !options.aud){
    throw new Error('Expected holder binding, but no aud or nonce is present.')
  }
  const parts = [serialized_sd_jwt, ...hs_disclosures]
  if (sd_jwt_payload.cnf && options.aud && options.nonce){
    serialized_holder_binding_jwt = await _create_holder_binding_jwt(options.nonce, options.aud, options.holderPrivateKey)
    parts.push(serialized_holder_binding_jwt)
  }
  const combined_presentation = _combine(...parts)
  return combined_presentation;
}

// https://github.com/oauth-wg/oauth-selective-disclosure-jwt/blob/7aa6f926bfc684eae530ebf1210d74b636ae0a06/sd_jwt/operations.py#L401
const _verify_sd_jwt = async (serialized_sd_jwt: string, cb_get_issuer_key: any)=>{
  const publicKey =  cb_get_issuer_key();
  const { payload, protectedHeader } = await jose.compactVerify(serialized_sd_jwt, await jose.importJWK(publicKey))
  return { payload: JSON.parse(new TextDecoder().decode(payload).toString()), protectedHeader }
}

// https://github.com/oauth-wg/oauth-selective-disclosure-jwt/blob/7aa6f926bfc684eae530ebf1210d74b636ae0a06/sd_jwt/operations.py#L389
const _parse_combined_presentation = (combined: string) => {

  const [_unverified_input_sd_jwt, ..._hs_disclosures] = _split(combined)
  let _unverified_input_holder_binding_jwt = undefined
  if (_hs_disclosures[_hs_disclosures.length-1].includes('.')){
    // its a JWT
    _unverified_input_holder_binding_jwt = _hs_disclosures.pop()
  }

  return {_unverified_input_sd_jwt, _hs_disclosures, _unverified_input_holder_binding_jwt}
}

// https://github.com/oauth-wg/oauth-selective-disclosure-jwt/blob/7aa6f926bfc684eae530ebf1210d74b636ae0a06/sd_jwt/operations.py#L417
const _verify_holder_binding_jwt = async (jwt: string, expected_aud: any, expected_nonce: any, holderPublicKey:any) => {
  const { payload } = await jose.jwtVerify(jwt, await jose.importJWK(holderPublicKey), {
    audience: expected_aud,
  })
  return payload.nonce === expected_nonce;
}

// https://github.com/oauth-wg/oauth-selective-disclosure-jwt/blob/7aa6f926bfc684eae530ebf1210d74b636ae0a06/sd_jwt/operations.py#L460
const _unpack_disclosed_claims = (sd_jwt_claims: any, _duplicate_hash_check: any[], _hash_to_decoded_disclosure: any): any => {
  if (Array.isArray(sd_jwt_claims)){
    return sd_jwt_claims.map((c: any)=>{ return _unpack_disclosed_claims(c, _duplicate_hash_check, _hash_to_decoded_disclosure) })
  } else if (typeof sd_jwt_claims === 'object'){
    // # First, try to figure out if there are any claims to be
    // # disclosed in this dict. If so, replace them by their
    // # disclosed values.
    const pre_output:any = {}
    for (const [key, value] of Object.entries(sd_jwt_claims)) {
      if (key !== SD_DIGESTS_KEY){
        pre_output[key] = _unpack_disclosed_claims(value, _duplicate_hash_check, _hash_to_decoded_disclosure)
      }
    }
    for ( const digest of sd_jwt_claims[SD_DIGESTS_KEY] || []){
      if (_duplicate_hash_check.includes(digest)){
        throw new Error(`Duplicate hash found in SD-JWT: ${digest}`)
      }
      _duplicate_hash_check.push(digest);
      if (_hash_to_decoded_disclosure[digest]){
        const [_salt, key, value] = _hash_to_decoded_disclosure[digest];
        if (pre_output[key]){
          throw new Error(`Duplicate key found when unpacking disclosed claim: '${key}' in ${pre_output}. This is not allowed.`)
        }
        const unpacked_value = _unpack_disclosed_claims(value, _duplicate_hash_check, _hash_to_decoded_disclosure)
        pre_output[key] = unpacked_value
      }
    }
    return pre_output
  } else {
    return sd_jwt_claims
  }
}

// https://github.com/oauth-wg/oauth-selective-disclosure-jwt/blob/7aa6f926bfc684eae530ebf1210d74b636ae0a06/sd_jwt/operations.py#L451
const _extract_sd_claims = (_sd_jwt_payload: any, _hash_to_decoded_disclosure: any) =>{
  if (_sd_jwt_payload[DIGEST_ALG_KEY] !== 'sha-256'){
    throw new Error('Invalid hash algorithm')
  }
  const _duplicate_hash_check:any = []
  return _unpack_disclosed_claims(_sd_jwt_payload, _duplicate_hash_check, _hash_to_decoded_disclosure)
}

export const verify = async (sd_jwt_combined: string, options: any) => {
  const {_unverified_input_sd_jwt, _hs_disclosures, _unverified_input_holder_binding_jwt} = _parse_combined_presentation(sd_jwt_combined)
  const {_hash_to_decoded_disclosure, _hash_to_disclosure} = _create_hash_mappings(_hs_disclosures)
  const {protectedHeader, payload} = await  _verify_sd_jwt(_unverified_input_sd_jwt, () => {
    return options.issuerPublicKey
  })

  if (payload.cnf){
    if (!_unverified_input_holder_binding_jwt){
      throw new Error('Expected holder binding, but found no token.')
    }
    if (options.expected_aud || options.expected_nonce){
      if (! (options.expected_aud && options.expected_nonce)){
        throw new Error('Either both expected_aud and expected_nonce must be set or both must be undefined')
      }
    }
    await _verify_holder_binding_jwt(_unverified_input_holder_binding_jwt, options.expected_aud, options.expected_nonce,  payload.cnf.jwk)
  }
  const presentationOutput = _extract_sd_claims(payload, _hash_to_decoded_disclosure)
  return {protectedHeader, payload: presentationOutput}
}