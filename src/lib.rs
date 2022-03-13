/// initial hash value as described in FIPS PUB 180-4 section 5.3.3
const INITIAL_HASH_VALUE: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// cube root constants as described in FIPS PUB 180-4 section 4.2.2
const CUBE_ROOTS_CONSTANTS: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// bitwise / logical complement macro
macro_rules! cmp {
    ($a:expr) => {
        (!$a)
    };
}

/// bitwise AND macro
macro_rules! and {
    ($a:expr, $b:expr) => {
        ($a & $b)
    };
}

/// bitwise XOR macro
macro_rules! xor  {
    ($a:expr, $b:expr) => {
        ($a ^ $b)
    };
    ($a:expr, $($b:expr),+) => {
        xor!($a, xor!($($b),+))
    };
}

/// right shift macro as described in FIPS PUB 180-4 section 3.2
macro_rules! shr {
    ($value:expr, $bits:expr) => {
        ($value >> $bits)
    };
}

/// circular right shift macro as described in FIPS PUB 180-4 section 3.2
/// warning: shift by more than 31 bits will result in an overflow
macro_rules! rotr32 {
    ($value:expr, $bits:expr) => {
        ($value >> $bits | ($value << (32 - $bits)))
    };
}

/// circular left shift macro as described in FIPS PUB 180-4 section 3.2
/// warning: shift by more than 31 bits will result in an overflow
macro_rules! rotl32 {
    ($value:expr, $bits:expr) => {
        ($value << $bits | ($value >> (32 - $bits)))
    };
}

/// ch macro as described in FIPS PUB 180-4 section 4.1.2
macro_rules! ch {
    ($x:expr, $y:expr, $z:expr) => {
        xor!(and!($x, $y), and!(cmp!($x), $z))
    };
}

/// maj macro as described in FIPS PUB 180-4 section 4.1.2
macro_rules! maj {
    ($x:expr, $y:expr, $z:expr) => {
        xor!(and!($x, $y), and!($x, $z), and!($y, $z))
    };
}

/// upper case sigma 0 macro as described in FIPS PUB 180-4 section 4.1.2
macro_rules! ucs0 {
    ($x:expr) => {
        xor!(rotr32!($x, 2), rotr32!($x, 13), rotr32!($x, 22))
    };
}

/// upper case sigma 1 macro as described in FIPS PUB 180-4 section 4.1.2
macro_rules! ucs1 {
    ($x:expr) => {
        xor!(rotr32!($x, 6), rotr32!($x, 11), rotr32!($x, 25))
    };
}

/// lower case sigma 0 macro as described in FIPS PUB 180-4 section 4.1.2
macro_rules! lcs0 {
    ($x:expr) => {
        xor!(rotr32!($x, 7), rotr32!($x, 18), shr!($x, 3))
    };
}

/// lower case sigma 1 macro as described in FIPS PUB 180-4 section 4.1.2
macro_rules! lcs1 {
    ($x:expr) => {
        xor!(rotr32!($x, 17), rotr32!($x, 19), shr!($x, 10))
    };
}

/// modulo 2^32 addition
macro_rules! add32 {
    ($a:expr, $b:expr) => {
        (($a as u64 + $b as u64) as u32)
    };
    ($a:expr, $($b:expr),+) => {
        add32!($a, add32!($($b),+))
    };
}

/// computes an intermediate hash during the sha256 computation
fn compute_intermediate_digest(
    intermediate_digest: &mut [u32; 8],
    message_shedule: &mut [u32; 64],
) {
    // the following calculations are implemented as described in
    // FIPS PUB 180-4 section 6.2.2

    // complete the preparation of the message schedule
    for i in 16..64 {
        message_shedule[i] = add32!(
            lcs1!(message_shedule[i - 2]),
            message_shedule[i - 7],
            lcs0!(message_shedule[i - 15]),
            message_shedule[i - 16]
        );
    }

    /*for i in 0..16 {
        println!("W[{}] = {:08X}", i, message_shedule[i]);
    }*/

    // initialize the eight working variables
    let mut a = intermediate_digest[0];
    let mut b = intermediate_digest[1];
    let mut c = intermediate_digest[2];
    let mut d = intermediate_digest[3];
    let mut e = intermediate_digest[4];
    let mut f = intermediate_digest[5];
    let mut g = intermediate_digest[6];
    let mut h = intermediate_digest[7];

    // do some calculations as described in point 3 of section 6.2.2
    for i in 0..64 {
        let t1 = add32!(
            h,
            ucs1!(e),
            ch!(e, f, g),
            CUBE_ROOTS_CONSTANTS[i],
            message_shedule[i]
        );
        let t2 = add32!(ucs0!(a), maj!(a, b, c));
        h = g;
        g = f;
        f = e;
        e = add32!(d, t1);
        d = c;
        c = b;
        b = a;
        a = add32!(t1, t2);

        /*println!(
            "t= {}: {:08X} {:08X} {:08X} {:08X} {:08X} {:08X} {:08X} {:08X}",
            i, a, b, c, d, e, f, g, h
        );*/
    }

    // compute the new intermediate digest
    intermediate_digest[0] = add32!(a, intermediate_digest[0]);
    intermediate_digest[1] = add32!(b, intermediate_digest[1]);
    intermediate_digest[2] = add32!(c, intermediate_digest[2]);
    intermediate_digest[3] = add32!(d, intermediate_digest[3]);
    intermediate_digest[4] = add32!(e, intermediate_digest[4]);
    intermediate_digest[5] = add32!(f, intermediate_digest[5]);
    intermediate_digest[6] = add32!(g, intermediate_digest[6]);
    intermediate_digest[7] = add32!(h, intermediate_digest[7]);
}

/// calculates the sha256 for a given message
fn compute_sha256_digest(message: &[u8]) -> [u32; 8] {
    let mut intermediate_digest = INITIAL_HASH_VALUE;
    let mut message_schedule = [0u32; 64];
    let mut message_position: usize = 0;
    let mut data_left = message.len();

    // the following code splits the message into 512 bit blocks and calculates
    // the intermediate digest for each block
    while data_left > 0 {
        if data_left <= 64 {
            // initialize a new message digest block filled with zeros. (Because
            // adding of data is done by or operator)
            message_schedule = [0u32; 64];

            // put the bytes from the message into the message schedule block
            for i in message_position..message.len() {
                message_schedule[(i / 4) % 16] |= (message[i] as u32) << (24 - ((i % 4) * 8));
            }
            message_position = message.len();

            // closure for adding a termination bit to the end of the message
            // within the message schedule block
            let mut add_termination_bit = |message_schedule: &mut [u32; 64]| {
                message_schedule[(message_position / 4) % 16] |=
                    (0x80 as u32) << (24 - ((message_position % 4) * 8));
            };

            // if data_left is smaller than 64 bytes, then add the termination
            // bit to the current block.
            if data_left < 64 {
                add_termination_bit(&mut message_schedule);
            }

            // check if the length information fits in the current message
            // schedule block. If it does not fit, then compute the current
            // block and create a new empty one.
            if data_left >= 56 {
                compute_intermediate_digest(&mut intermediate_digest, &mut message_schedule);
                message_schedule = [0u32; 64];
            }

            // if data_left is exactly 64 bytes, then add the termination bit to
            // the new block
            if data_left == 64 {
                add_termination_bit(&mut message_schedule);
            }

            // add the message length at the end of the message schedule block
            let message_len = message.len() * 8;
            message_schedule[15] = message_len as u32;
            message_schedule[14] = (message_len >> 32) as u32;
        } else {
            // put the bytes from the message into the message schedule block
            for i in 0..16 {
                let j = i * 4;
                message_schedule[i] = ((message[j + 0] as u32) << 24
                    | (message[j + 1] as u32) << 16
                    | (message[j + 2] as u32) << 8
                    | (message[j + 3] as u32)) as u32
            }
            message_position += 64;
        }

        // do the calculations for the current block
        compute_intermediate_digest(&mut intermediate_digest, &mut message_schedule);

        data_left = message.len() - message_position;
    }

    // return the intermediate digest as result of the sha256 calculation
    intermediate_digest
}

#[cfg(test)]
mod tests {
    use crate::compute_sha256_digest;

    #[test]
    fn test_calculate_sha256_with_one_block() {
        let message = "abc";
        let expected_digest: [u32; 8] = [
            0xBA7816BF, 0x8F01CFEA, 0x414140DE, 0x5DAE2223, 0xB00361A3, 0x96177A9C, 0xB410FF61,
            0xF20015AD,
        ];

        let digest = compute_sha256_digest(message.as_bytes());

        assert_eq!(digest, expected_digest);
    }

    #[test]
    fn test_calculate_sha256_with_two_blocks() {
        let message = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        let expected_digest: [u32; 8] = [
            0x248D6A61, 0xD20638B8, 0xE5C02693, 0x0C3E6039, 0xA33CE459, 0x64FF2167, 0xF6ECEDD4,
            0x19DB06C1,
        ];

        let digest = compute_sha256_digest(message.as_bytes());

        assert_eq!(digest, expected_digest);
    }

    #[test]
    fn test_calculate_sha256_with_data_size_equal_block_size() {
        let message = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopqopqrpqrs";
        let expected_digest: [u32; 8] = [
            0x5a5748c5, 0xc07341a6, 0xc8b2c06b, 0xa633247d, 0xc04b712d, 0x28fd2951, 0xcc911609,
            0x15902d67,
        ];

        let digest = compute_sha256_digest(message.as_bytes());

        assert_eq!(digest, expected_digest);
    }

    #[test]
    fn test_cmp_macro() {
        let result = cmp!(0x00000000u32);
        assert_eq!(result, 0xffffffffu32);

        let result = cmp!(1i32);
        assert_eq!(result, -2i32);

        let result = cmp!(true);
        assert_eq!(result, false);
    }

    #[test]
    fn test_and_macro() {
        let result = and!(0b0101u32, 0b0011u32);
        assert_eq!(result, 0b0001u32);
    }

    #[test]
    fn test_xor_macro() {
        let result = xor!(0b0101u32, 0b0011u32);
        assert_eq!(result, 0b0110u32);

        let result = xor!(1u32, 1u32, 1u32);
        assert_eq!(result, 1u32);
    }

    #[test]
    fn test_shr_macro() {
        let result = shr!(0xffffffffu32, 3);
        assert_eq!(result, 0x1fffffffu32);

        let result = shr!(0xffffffffu32, 10);
        assert_eq!(result, 0x003fffffu32);
    }

    #[test]
    fn test_rotr32_macro() {
        let result = rotr32!(0x00000002u32, 1);
        assert_eq!(result, 0x00000001u32);
    }

    #[test]
    fn test_rotl32_macro() {
        let result = rotl32!(0x00000001u32, 1);
        assert_eq!(result, 0x00000002u32);
    }

    #[test]
    fn test_ch_macro() {
        let result = ch!(0x00000000u32, 0x00000000u32, 0x00000000u32);
        assert_eq!(result, 0x00000000u32);

        let result = ch!(0x12345678u32, 0xabcdef01u32, 0x01010101u32);
        assert_eq!(result, 0x03054701u32);
    }

    #[test]
    fn test_not_macro() {
        let result = maj!(0x00000000u32, 0x00000000u32, 0x00000000u32);
        assert_eq!(result, 0x00000000u32);

        let result = maj!(0x12345678u32, 0xabcdef01u32, 0x01010101u32);
        assert_eq!(result, 0x03054701u32);
    }

    #[test]
    fn test_ucs0_macro() {
        let result = ucs0!(0x00000000u32);
        assert_eq!(result, 0x00000000u32);

        let result = ucs0!(0x1234abcdu32);
        assert_eq!(result, 0xC84A8F1Eu32);
    }

    #[test]
    fn test_ucs1_macro() {
        let result = ucs1!(0x00000000u32);
        assert_eq!(result, 0x00000000u32);

        let result = ucs1!(0x1234abcdu32);
        assert_eq!(result, 0x57BF72B3u32);
    }

    #[test]
    fn test_lcs0_macro() {
        let result = lcs0!(0x00000000u32);
        assert_eq!(result, 0x00000000u32);

        let result = lcs0!(0x1234abcdu32);
        assert_eq!(result, 0xB291B8A3u32);
    }

    #[test]
    fn test_lcs1_macro() {
        let result = lcs1!(0x00000000u32);
        assert_eq!(result, 0x00000000u32);

        let result = lcs1!(0x1234abcdu32);
        assert_eq!(result, 0xC09BA676u32);
    }

    #[test]
    fn test_add32_macro() {
        let result = add32!(0x00000000u32, 0x00000000u32);
        assert_eq!(result, 0x00000000u32);

        let result = add32!(0xffffffffu32, 0x00000001u32, 0x00000001u32);
        assert_eq!(result, 0x00000001u32);

        let result = add32!(0xffffffffu32, 0xffffffffu32);
        assert_eq!(result, 0xfffffffeu32);
    }
}
