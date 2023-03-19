import crypto from "crypto";
import * as jose from "jose";

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
const _assemble_sd_jwt_payload = (user_claims: any, ii_disclosures: any[], _debug_ii_disclosures_contents: any[]) => {
  const sd_jwt_payload = _create_sd_claims(user_claims, ii_disclosures, _debug_ii_disclosures_contents);
  sd_jwt_payload[DIGEST_ALG_KEY] = 'sha-256';
  // TODO: holder key / cnf
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
export const sign = async (header: any, user_claims: any, privateKey: any) => {
  _check_for_sd_claim(user_claims);

  const ii_disclosures:any[] = [];
  const _debug_ii_disclosures_contents:any[] = [];
  
  const sd_jwt_payload = _assemble_sd_jwt_payload(user_claims, ii_disclosures, _debug_ii_disclosures_contents);
  const serialized_sd_jwt = await _create_signed_jwt(header, sd_jwt_payload, privateKey);
  const combined = _create_combined(serialized_sd_jwt, ii_disclosures)
  return combined;
};
