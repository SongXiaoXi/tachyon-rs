
#[allow(non_upper_case_globals)]
const Nb: usize = 4;
#[allow(non_upper_case_globals)]
const Nk128: usize = 4;
#[allow(non_upper_case_globals)]
const Nr128: usize = 10;
#[allow(non_upper_case_globals)]
const RCON: [u8; 11] = [
    0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
];

#[inline(always)]
fn key_expansion_128(key: &[u8; 16], round_key: &mut [u8; 176]) {
    let mut temp: [u8; 4] = [0; 4];
    let mut i: usize = 0;

    while i < Nk128 {
        round_key[i * 4] = key[i * 4];
        round_key[i * 4 + 1] = key[i * 4 + 1];
        round_key[i * 4 + 2] = key[i * 4 + 2];
        round_key[i * 4 + 3] = key[i * 4 + 3];
        i += 1;
    }

    i = Nk128;
    while i < Nb * (Nr128 + 1) {
        temp[0] = round_key[(i - 1) * 4];
        temp[1] = round_key[(i - 1) * 4 + 1];
        temp[2] = round_key[(i - 1) * 4 + 2];
        temp[3] = round_key[(i - 1) * 4 + 3];

        if i % Nk128 == 0 {
            // This function shifts the 4 bytes in a word to the left once.
            // [a0,a1,a2,a3] becomes [a1,a2,a3,a0]
            
            // Function RotWord()
            let u8tmp = temp[0];
            temp[0] = temp[1];
            temp[1] = temp[2];
            temp[2] = temp[3];
            temp[3] = u8tmp;

            // SubWord() is a function that takes a four-byte input word and
            // applies the S-box to each of the four bytes to produce an output word.
            
            // Function Subword()
            temp[0] = SBOX[temp[0] as usize];
            temp[1] = SBOX[temp[1] as usize];
            temp[2] = SBOX[temp[2] as usize];
            temp[3] = SBOX[temp[3] as usize];

            temp[0] = temp[0] ^ RCON[i / Nk128];
        }

        let j = i * 4;
        let k = (i - Nk128) * 4;
        round_key[j] = round_key[k] ^ temp[0];
        round_key[j + 1] = round_key[k + 1] ^ temp[1];
        round_key[j + 2] = round_key[k + 2] ^ temp[2];
        round_key[j + 3] = round_key[k + 3] ^ temp[3];
        i += 1;
    }
}

#[inline(always)]
fn add_round_key(state: &mut [u8; 16], round_key: &[u8; 176], round: usize) {
    let mut i: usize = 0;
    while i < 4 {
        state[i * 4] ^= round_key[round * Nb * 4 + i * Nb];
        state[i * 4 + 1] ^= round_key[round * Nb * 4 + i * Nb + 1];
        state[i * 4 + 2] ^= round_key[round * Nb * 4 + i * Nb + 2];
        state[i * 4 + 3] ^= round_key[round * Nb * 4 + i * Nb + 3];
        i += 1;
    }
}

// The SubBytes Function Substitutes the values in the
// state matrix with values in an S-box.
#[inline(always)]
fn sub_bytes(state: &mut [u8; 16]) {
    let mut i: usize = 0;
    while i < 16 {
        state[i] = SBOX[state[i] as usize];
        i += 1;
    }
}

// The ShiftRows() function shifts the rows in the state to the left.
// Each row is shifted with different offset.
// Offset = Row number. So the first row is not shifted.
#[inline(always)]
fn shift_rows(state: &mut [u8; 16]) {
    let mut u8tmp: u8 = state[1];
    state[1] = state[5];
    state[5] = state[9];
    state[9] = state[13];
    state[13] = u8tmp;

    u8tmp = state[2];
    state[2] = state[10];
    state[10] = u8tmp;
    u8tmp = state[6];
    state[6] = state[14];
    state[14] = u8tmp;

    u8tmp = state[3];
    state[3] = state[15];
    state[15] = state[11];
    state[11] = state[7];
    state[7] = u8tmp;
}

#[inline(always)]
fn xtime(x: u8) -> u8 {
    (x << 1) ^ (((x >> 7) & 1) * 0x1b)
}

// MixColumns function mixes the columns of the state matrix
#[inline(always)]
fn mix_columns(state: &mut [u8; 16]) {
    for i in 0..4 {
        let t = state[i * 4];
        let tmp = state[i * 4] ^ state[i * 4 + 1] ^ state[i * 4 + 2] ^ state[i * 4 + 3];
        let mut tm = state[i * 4] ^ state[i * 4 + 1];
        tm = xtime(tm);
        state[i * 4] ^= tm ^ tmp;
        tm = state[i * 4 + 1] ^ state[i * 4 + 2];
        tm = xtime(tm);
        state[i * 4 + 1] ^= tm ^ tmp;
        tm = state[i * 4 + 2] ^ state[i * 4 + 3];
        tm = xtime(tm);
        state[i * 4 + 2] ^= tm ^ tmp;
        tm = state[i * 4 + 3] ^ t;
        tm = xtime(tm);
        state[i * 4 + 3] ^= tm ^ tmp;
    }
}

// Multiply is used to multiply numbers in the field GF(2^8)
// Note: The last call to xtime() is unneeded, but often ends up generating a smaller binary
//       The compiler seems to be able to vectorize the operation better this way.
#[inline(always)]
fn multiply(x: u8, y: u8) -> u8 {
    (((y & 1) * x) ^ ((y >> 1 & 1) * xtime(x)) ^ ((y >> 2 & 1) * xtime(xtime(x))) ^ ((y >> 3 & 1) * xtime(xtime(xtime(x)))) ^ ((y >> 4 & 1) * xtime(xtime(xtime(xtime(x)))))) as u8
}

// MixColumns function mixes the columns of the state matrix.
// The method used to multiply may be difficult to understand for the inexperienced.
// Please use the references to gain more information.
#[inline(always)]
fn inv_mix_columns(state: &mut [u8; 16]) {
    for i in 0..4 {
        let a = state[i * 4];
        let b = state[i * 4 + 1];
        let c = state[i * 4 + 2];
        let d = state[i * 4 + 3];

        state[i * 4] = multiply(a, 0x0e) ^ multiply(b, 0x0b) ^ multiply(c, 0x0d) ^ multiply(d, 0x09);
        state[i * 4 + 1] = multiply(a, 0x09) ^ multiply(b, 0x0e) ^ multiply(c, 0x0b) ^ multiply(d, 0x0d);
        state[i * 4 + 2] = multiply(a, 0x0d) ^ multiply(b, 0x09) ^ multiply(c, 0x0e) ^ multiply(d, 0x0b);
        state[i * 4 + 3] = multiply(a, 0x0b) ^ multiply(b, 0x0d) ^ multiply(c, 0x09) ^ multiply(d, 0x0e);
    }
}

// The SubBytes Function Substitutes the values in the
// state matrix with values in an S-box.
#[inline(always)]
fn inv_sub_bytes(state: &mut [u8; 16]) {
    let mut i: usize = 0;
    while i < 16 {
        state[i] = RSBOX[state[i] as usize];
        i += 1;
    }
}

fn inv_shift_rows(state: &mut [u8; 16]) {
    let mut u8tmp: u8 = state[13];
    state[13] = state[9];
    state[9] = state[5];
    state[5] = state[1];
    state[1] = u8tmp;

    u8tmp = state[2];
    state[2] = state[10];
    state[10] = u8tmp;
    u8tmp = state[6];
    state[6] = state[14];
    state[14] = u8tmp;

    u8tmp = state[3];
    state[3] = state[7];
    state[7] = state[11];
    state[11] = state[15];
    state[15] = u8tmp;
}

// Cipher is the main function that encrypts the PlainText.
#[inline(always)]
fn cipher_inplace(state: &mut [u8; 16], round_key: &[u8; 176]) {
    add_round_key(state, round_key, 0);

    let mut i: usize = 1;
    while i < Nr128 {
        sub_bytes(state);
        shift_rows(state);
        mix_columns(state);
        add_round_key(state, round_key, i);
        i += 1;
    }

    sub_bytes(state);
    shift_rows(state);
    add_round_key(state, round_key, Nr128);
}

#[inline(always)]
fn cipher(input: &[u8; 16], output: &mut [u8; 16], round_key: &[u8; 176]) {
    let mut state: [u8; 16] = [0; 16];
    let mut i: usize = 0;
    while i < 16 {
        state[i] = input[i];
        i += 1;
    }

    cipher_inplace(&mut state, round_key);

    i = 0;
    while i < 16 {
        output[i] = state[i];
        i += 1;
    }
}

// InvCipher is the main function that decrypts the CipherText.
#[inline(always)]
fn inv_cipher_inplace(state: &mut [u8; 16], round_key: &[u8; 176]) {
    add_round_key(state, round_key, Nr128);

    let mut i: usize = Nr128 - 1;
    while i > 0 {
        inv_shift_rows(state);
        inv_sub_bytes(state);
        add_round_key(state, round_key, i);
        inv_mix_columns(state);
        i -= 1;
    }

    inv_shift_rows(state);
    inv_sub_bytes(state);
    add_round_key(state, round_key, 0);
}

#[inline(always)]
fn inv_cipher(input: &[u8; 16], output: &mut [u8; 16], round_key: &[u8; 176]) {
    let mut state: [u8; 16] = [0; 16];
    let mut i: usize = 0;
    while i < 16 {
        state[i] = input[i];
        i += 1;
    }

    inv_cipher_inplace(&mut state, round_key);

    i = 0;
    while i < 16 {
        output[i] = state[i];
        i += 1;
    }
}

#[derive(Clone)]
pub struct AES128 {
    round_key: [u8; 176],
}

impl AES128 {
    pub const BLOCK_LEN: usize = 16;
    pub const KEY_LEN: usize = 16;
    #[inline(always)]
    pub fn new(key: &[u8; 16]) -> Self {
        let mut round_key: [u8; 176] = [0; 176];
        key_expansion_128(key, &mut round_key);
        Self { round_key }
    }

    #[inline(always)]
    pub fn from_slice(key: &[u8]) -> Self {
        assert_eq!(key.len(), 16);
        Self::new(unsafe { &*(key.as_ptr() as *const [u8; 16]) })
    }

    #[inline(always)]
    pub fn encrypt(&self, data: &mut [u8; 16]) {
        cipher_inplace(data, &self.round_key);
    }

    #[inline(always)]
    pub fn encrypt_copy(&self, data: &[u8; 16], output: &mut [u8; 16]) {
        cipher(data, output, &self.round_key);
    }

    #[inline(always)]
    pub fn decrypt(&self, data: &mut [u8; 16]) {
        inv_cipher_inplace(data, &self.round_key);
    }

    #[inline(always)]
    pub fn decrypt_copy(&self, data: &[u8; 16], output: &mut [u8; 16]) {
        inv_cipher(data, output, &self.round_key);
    }
}

const SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
];

const RSBOX: [u8; 256] = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes128() {
        let key = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c];
        let cipher = AES128::new(&key);

        let mut data = [0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34];
        cipher.encrypt(&mut data);
        assert_eq!(data, [0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb, 0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32]);

        let mut data = [0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb, 0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32];
        cipher.decrypt(&mut data);
        assert_eq!(data, [0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34]);
    }
}