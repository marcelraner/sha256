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
macro_rules! and  {
    ($a:expr, $b:expr) => {
        ($a & $b)
    };
}

/// bitwise OR macro
macro_rules! or  {
    ($a:expr, $b:expr) => {
        ($a | $b)
    };
    ($a:expr, $($b:expr),+) => {
        ($a ^ or!($($b),+))
    };
}

/// bitwise XOR macro
macro_rules! xor  {
    ($a:expr, $b:expr) => {
        ($a ^ $b)
    };
    ($a:expr, $($b:expr),+) => {
        ($a ^ xor!($($b),+))
    };
}

/// right shift macro as described in FIPS PUB 180-4 section 3.2
macro_rules! shr  {
    ($value:expr, $bits:expr) => {
        ($value >> $bits)
    };
}

/// circular right shift macro as described in FIPS PUB 180-4 section 3.2
/// warning: shift by more than 31 bits will result in an overflow
macro_rules! rotr32  {
    ($value:expr, $bits:expr) => {
        ($value >> $bits | ($value << (32 - $bits)))
    };
}

/// circular left shift macro as described in FIPS PUB 180-4 section 3.2
/// warning: shift by more than 31 bits will result in an overflow
macro_rules! rotl32  {
    ($value:expr, $bits:expr) => {
        ($value << $bits | ($value >> (32 - $bits)))
    };
}

/// ch macro as described in FIPS PUB 180-4 section 4.1.2
macro_rules! ch  {
    ($x:expr, $y:expr, $z:expr) => {
        xor!(and!($x, $y), and!(cmp!($x), $z))
    };
}

/// maj macro as described in FIPS PUB 180-4 section 4.1.2
macro_rules! maj  {
    ($x:expr, $y:expr, $z:expr) => {
        xor!(and!($x, $y), and!($x, $z), and!($y, $z))
    };
}

/// upper case sigma 0 macro as described in FIPS PUB 180-4 section 4.1.2
macro_rules! ucs0  {
    ($x:expr) => {
        xor!(rotr32!($x, 2), rotr32!($x, 13), rotr32!($x, 22))
    };
}

/// upper case sigma 1 macro as described in FIPS PUB 180-4 section 4.1.2
macro_rules! ucs1  {
    ($x:expr) => {
        xor!(rotr32!($x, 6), rotr32!($x, 11), rotr32!($x, 25))
    };
}

/// lower case sigma 0 macro as described in FIPS PUB 180-4 section 4.1.2
macro_rules! lcs0  {
    ($x:expr) => {
        xor!(rotr32!($x, 7), rotr32!($x, 18), shr!($x, 3))
    };
}

/// lower case sigma 1 macro as described in FIPS PUB 180-4 section 4.1.2
macro_rules! lcs1  {
    ($x:expr) => {
        xor!(rotr32!($x, 17), rotr32!($x, 19), shr!($x, 10))
    };
}

#[cfg(test)]
mod tests {
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
    fn test_or_macro() {
        let result = or!(0b0101u32, 0b0011u32);
        assert_eq!(result, 0b0111u32);
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

        todo!();
    }

    #[test]
    fn test_ucs1_macro() {
        let result = ucs1!(0x00000000u32);
        assert_eq!(result, 0x00000000u32);

        todo!();
    }

    #[test]
    fn test_lcs0_macro() {
        let result = lcs0!(0x00000000u32);
        assert_eq!(result, 0x00000000u32);

        todo!();
    }

    #[test]
    fn test_lcs1_macro() {
        let result = lcs1!(0x00000000u32);
        assert_eq!(result, 0x00000000u32);

        todo!();
    }
}
