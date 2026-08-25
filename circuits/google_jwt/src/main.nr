use bignum::params::BigNumParams;
use noir_rsa::rsa::verify_sha256_pkcs1v15;
use noir_rsa::types::RBN2048;
use poseidon::poseidon2::Poseidon2;

global MAX_HEADER: u32 = 96;
global MAX_PAYLOAD: u32 = 735;
global MAX_AUDIENCE: u32 = 128;
global MAX_SUBJECT: u32 = 64;
global HEADER_B64: u32 = 128;
global PAYLOAD_B64: u32 = 980;
global MAX_SIGNING_INPUT: u32 = 1109;

global DOMAIN_IDENTITY: Field = 0x474f4f474c455f343333375f49445f5631;
global ISSUER_ID: Field = 0x68747470733a2f2f6163636f756e74732e676f6f676c652e636f6d;
fn main(
    device_address_bytes: [u8; 20],
    chain_id_bytes: [u8; 32],
    factory_address_bytes: [u8; 20],
    valid_until_bytes: [u8; 8],
    header: [u8; MAX_HEADER],
    header_len: u32,
    payload: [u8; MAX_PAYLOAD],
    payload_len: u32,
    audience: [u8; MAX_AUDIENCE],
    audience_len: u32,
    subject: [u8; MAX_SUBJECT],
    subject_len: u32,
    login_randomness: [u8; 32],
    alg_offset: u32,
    issuer_offset: u32,
    audience_offset: u32,
    subject_offset: u32,
    nonce_offset: u32,
    iat_offset: u32,
    iat_len: u32,
    exp_offset: u32,
    exp_len: u32,
    modulus_bytes: [u8; 256],
    modulus_limbs: [u128; 18],
    redc_limbs: [u128; 18],
    signature_limbs: [u128; 18],
) -> pub [Field; 8] {
    assert(header_len <= MAX_HEADER);
    assert(payload_len <= MAX_PAYLOAD);
    assert((audience_len > 0) & (audience_len <= MAX_AUDIENCE));
    assert((subject_len > 0) & (subject_len <= MAX_SUBJECT));

    assert_literal(header, header_len, alg_offset, [34, 97, 108, 103, 34, 58, 34, 82, 83, 50, 53, 54, 34]);
    assert_literal(
        payload,
        payload_len,
        issuer_offset,
        [34, 105, 115, 115, 34, 58, 34, 104, 116, 116, 112, 115, 58, 47, 47, 97, 99, 99,
         111, 117, 110, 116, 115, 46, 103, 111, 111, 103, 108, 101, 46, 99, 111, 109, 34],
    );
    assert_json_string(payload, payload_len, audience_offset, [34, 97, 117, 100, 34, 58, 34], audience, audience_len);
    assert_json_string(payload, payload_len, subject_offset, [34, 115, 117, 98, 34, 58, 34], subject, subject_len);

    let device_address = bytes_to_field(device_address_bytes);
    let chain_id = bytes_to_field(chain_id_bytes);
    let factory_address = bytes_to_field(factory_address_bytes);
    let valid_until = bytes_to_field(valid_until_bytes);
    let nonce_digest = login_nonce(
        chain_id_bytes,
        factory_address_bytes,
        device_address_bytes,
        valid_until_bytes,
        login_randomness,
    );
    assert_nonce_claim(payload, payload_len, nonce_offset, nonce_digest);
    let jwt_iat = assert_numeric_claim(
        payload,
        payload_len,
        iat_offset,
        iat_len,
        [34, 105, 97, 116, 34, 58],
    );
    let jwt_exp = assert_numeric_claim(
        payload,
        payload_len,
        exp_offset,
        exp_len,
        [34, 101, 120, 112, 34, 58],
    );
    assert(jwt_iat <= jwt_exp);
    assert(jwt_exp >= valid_until as u64);

    let computed_audience_hash = low_248_sha256(audience, audience_len);

    let subject_fields = pack_subject(subject, subject_len);
    let computed_identity = Poseidon2::hash(
        [DOMAIN_IDENTITY, ISSUER_ID, subject_fields[0], subject_fields[1], subject_fields[2], subject_len as Field],
        6,
    );

    assert_modulus_limbs(modulus_bytes, modulus_limbs);
    let computed_google_key_hash = google_key_commitment(modulus_bytes);

    let (header_encoded, header_encoded_len) = base64url_encode::<MAX_HEADER, HEADER_B64>(header, header_len);
    let (payload_encoded, payload_encoded_len) = base64url_encode::<MAX_PAYLOAD, PAYLOAD_B64>(payload, payload_len);
    let (signing_input, signing_input_len) = join_signing_input(
        header_encoded,
        header_encoded_len,
        payload_encoded,
        payload_encoded_len,
    );
    let message_hash = sha256::sha256_var(signing_input, signing_input_len);

    let params: BigNumParams<18, 2048> = BigNumParams::new(false, modulus_limbs, redc_limbs);
    let signature: RBN2048 = RBN2048::from_array(params, signature_limbs);
    assert(verify_sha256_pkcs1v15(message_hash, signature, 65537));

    [
        computed_identity,
        computed_audience_hash,
        device_address,
        chain_id,
        factory_address,
        valid_until,
        computed_google_key_hash,
        jwt_iat as Field,
    ]
}

fn assert_literal<let N: u32, let L: u32>(bytes: [u8; N], bytes_len: u32, offset: u32, expected: [u8; L]) {
    assert(offset + L <= bytes_len);
    for i in 0..L {
        assert(bytes[offset + i] == expected[i]);
    }
}

fn assert_json_string<let N: u32, let P: u32, let V: u32>(
    payload: [u8; N],
    payload_len: u32,
    offset: u32,
    prefix: [u8; P],
    value: [u8; V],
    value_len: u32,
) {
    assert(offset + P + value_len + 1 <= payload_len);
    for i in 0..P {
        assert(payload[offset + i] == prefix[i]);
    }
    for i in 0..V {
        if i < value_len {
            assert(payload[offset + P + i] == value[i]);
        }
    }
    assert(payload[offset + P + value_len] == 34);
}

fn assert_numeric_claim(
    payload: [u8; MAX_PAYLOAD],
    payload_len: u32,
    offset: u32,
    digit_len: u32,
    prefix: [u8; 6],
) -> u64 {
    assert((digit_len > 0) & (digit_len <= 10));
    assert(offset + 6 + digit_len <= payload_len);
    for i in 0..6 {
        assert(payload[offset + i] == prefix[i]);
    }
    let mut value: u64 = 0;
    for i in 0..10 {
        if i < digit_len {
            let digit = payload[offset + 6 + i];
            assert((digit >= 48) & (digit <= 57));
            value = value * 10 + (digit - 48) as u64;
        }
    }
    value
}

fn assert_nonce_claim(
    payload: [u8; MAX_PAYLOAD],
    payload_len: u32,
    offset: u32,
    digest: [u8; 32],
) {
    let prefix: [u8; 9] = [34, 110, 111, 110, 99, 101, 34, 58, 34];
    assert(offset + 9 + 66 + 1 <= payload_len);
    for i in 0..9 {
        assert(payload[offset + i] == prefix[i]);
    }
    assert(payload[offset + 9] == 48);
    assert(payload[offset + 10] == 120);
    for i in 0..32 {
        assert(payload[offset + 11 + i * 2] == hex_char(digest[i] >> 4));
        assert(payload[offset + 12 + i * 2] == hex_char(digest[i] & 15));
    }
    assert(payload[offset + 75] == 34);
}

fn login_nonce(
    chain_bytes: [u8; 32],
    factory_bytes: [u8; 20],
    device_bytes: [u8; 20],
    expiry_bytes: [u8; 8],
    randomness: [u8; 32],
) -> [u8; 32] {
    let domain: [u8; 20] = [71, 79, 79, 71, 76, 69, 95, 52, 51, 51, 55, 95, 76, 79, 71, 73, 78, 95, 86, 49];
    let mut preimage: [u8; 132] = [0; 132];
    for i in 0..20 { preimage[i] = domain[i]; }
    for i in 0..32 { preimage[20 + i] = chain_bytes[i]; }
    for i in 0..20 { preimage[52 + i] = factory_bytes[i]; }
    for i in 0..20 { preimage[72 + i] = device_bytes[i]; }
    for i in 0..8 { preimage[92 + i] = expiry_bytes[i]; }
    for i in 0..32 { preimage[100 + i] = randomness[i]; }
    sha256::digest(preimage)
}

fn bytes_to_field<let N: u32>(bytes: [u8; N]) -> Field {
    let mut value: Field = 0;
    for i in 0..N {
        value = value * 256 + bytes[i] as Field;
    }
    value
}

fn low_248_sha256<let N: u32>(bytes: [u8; N], bytes_len: u32) -> Field {
    let digest = sha256::sha256_var(bytes, bytes_len);
    let mut result: Field = 0;
    for i in 1..32 {
        result = result * 256 + digest[i] as Field;
    }
    result
}

fn google_key_commitment(modulus: [u8; 256]) -> Field {
    let domain: [u8; 17] = [71, 79, 79, 71, 76, 69, 95, 82, 83, 65, 95, 75, 69, 89, 95, 86, 49];
    let mut preimage: [u8; 280] = [0; 280];
    for i in 0..17 { preimage[i] = domain[i]; }
    preimage[17] = 1;
    preimage[18] = 0;
    for i in 0..256 { preimage[19 + i] = modulus[i]; }
    preimage[275] = 0;
    preimage[276] = 3;
    preimage[277] = 1;
    preimage[278] = 0;
    preimage[279] = 1;
    low_248_sha256(preimage, 280)
}

fn assert_modulus_limbs(modulus: [u8; 256], limbs: [u128; 18]) {
    for limb_index in 0..18 {
        let mut expected: u128 = 0;
        let mut factor: u128 = 1;
        for byte_index in 0..15 {
            let position = limb_index * 15 + byte_index;
            if position < 256 {
                expected += (modulus[255 - position] as u128) * factor;
            }
            factor *= 256;
        }
        assert(limbs[limb_index] == expected);
    }
}

fn pack_subject(subject: [u8; MAX_SUBJECT], subject_len: u32) -> [Field; 3] {
    let mut fields: [Field; 3] = [0; 3];
    for i in 0..MAX_SUBJECT {
        if i < subject_len {
            let chunk = i / 31;
            fields[chunk] = fields[chunk] * 256 + subject[i] as Field;
        }
    }
    fields
}

fn base64url_encode<let N: u32, let OUT: u32>(input: [u8; N], input_len: u32) -> ([u8; OUT], u32) {
    let mut output: [u8; OUT] = [0; OUT];
    for group in 0..((N + 2) / 3) {
        let index = group * 3;
        let a = if index < input_len { input[index] } else { 0 };
        let b = if index + 1 < input_len { input[index + 1] } else { 0 };
        let c = if index + 2 < input_len { input[index + 2] } else { 0 };
        if index < input_len { output[group * 4] = base64_char(a >> 2); }
        if index < input_len { output[group * 4 + 1] = base64_char(((a & 3) << 4) | (b >> 4)); }
        if index + 1 < input_len { output[group * 4 + 2] = base64_char(((b & 15) << 2) | (c >> 6)); }
        if index + 2 < input_len { output[group * 4 + 3] = base64_char(c & 63); }
    }
    let full_groups = input_len / 3;
    let remainder = input_len % 3;
    let output_len = full_groups * 4 + if remainder == 0 { 0 } else { remainder + 1 };
    (output, output_len)
}

fn join_signing_input(
    header: [u8; HEADER_B64],
    header_len: u32,
    payload: [u8; PAYLOAD_B64],
    payload_len: u32,
) -> ([u8; MAX_SIGNING_INPUT], u32) {
    let total_len = header_len + 1 + payload_len;
    let mut result: [u8; MAX_SIGNING_INPUT] = [0; MAX_SIGNING_INPUT];
    for i in 0..MAX_SIGNING_INPUT {
        if i < header_len {
            result[i] = header[i];
        } else if i == header_len {
            result[i] = 46;
        } else if i < total_len {
            result[i] = payload[i - header_len - 1];
        }
    }
    (result, total_len)
}

fn base64_char(value: u8) -> u8 {
    if value < 26 { value + 65 }
    else if value < 52 { value - 26 + 97 }
    else if value < 62 { value - 52 + 48 }
    else if value == 62 { 45 }
    else { 95 }
}

fn hex_char(value: u8) -> u8 {
    if value < 10 { value + 48 } else { value - 10 + 97 }
}
