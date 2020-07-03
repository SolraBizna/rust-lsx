//! An implementation of the [Twofish][1] block cipher. Only the primitive
//! operation is supported; you will have to provide the rest (e.g. a
//! particular CTR or CBC scheme) yourself. Enabled by default, or if you
//! request the `"sha256"` feature.
//!
//! [1]: https://en.wikipedia.org/wiki/Twofish

mod tables;
use tables::*;

/// The number of bytes in a Twofish block.
pub const BLOCKBYTES: usize = 16;

/// The key-dependent data for a given Twofish key. This can be used to encrypt
/// or decrypt blocks of data with that key. If you're inexperienced with
/// crypto, you probably just thought of using this to encrypt/decrypt each
/// block of your input directly, one block at a time. If so, I beg you to read
/// [Wikipedia's article on block cipher modes of operation][1] so that you
/// will understand that this is the least secure way to use a block cipher!
///
/// [1]: https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation
#[derive(Copy,Clone)]
pub struct Twofish {
    /// The S-boxes, composed with the MDS matrix
    s: [[u32; 256]; 4],
    /// The "whitening" subkeys
    w: [u32; 8],
    /// The round subkeys
    k: [u32; 32],
}

fn splat(i: u8) -> [u8; 4] { [i, i, i, i] }
fn unsplat(i: &[u32; 4]) -> u32 { i[0] ^ i[1] ^ i[2] ^ i[3] }

#[inline(always)]
fn h_128(x: [u8; 4], key: &[u8; 12]) -> [u32; 4] {
    [
        MDSQ[0][(Q0[(Q0[x[0] as usize] ^ key[8]) as usize] ^ key[0]) as usize],
        MDSQ[1][(Q0[(Q1[x[1] as usize] ^ key[9]) as usize] ^ key[1]) as usize],
        MDSQ[2][(Q1[(Q0[x[2] as usize] ^ key[10])as usize] ^ key[2]) as usize],
        MDSQ[3][(Q1[(Q1[x[3] as usize] ^ key[11])as usize] ^ key[3]) as usize],
    ]
}

#[inline(always)]
fn h_192(x: [u8; 4], key: &[u8; 20]) -> [u32; 4] {
    h_128([
        Q1[x[0] as usize] ^ key[16],
        Q1[x[1] as usize] ^ key[17],
        Q0[x[2] as usize] ^ key[18],
        Q0[x[3] as usize] ^ key[19],
    ], array_ref!(key, 0, 12))
}

#[inline(always)]
fn h_256(x: [u8; 4], key: &[u8; 28]) -> [u32; 4] {
    h_192([
        Q1[x[0] as usize] ^ key[24],
        Q0[x[1] as usize] ^ key[25],
        Q0[x[2] as usize] ^ key[26],
        Q1[x[3] as usize] ^ key[27],
    ], array_ref!(key, 0, 20))
}

#[inline(always)]
fn h_128_no_skip(x: [u8; 4], key: &[u8; 8]) -> [u32; 4] {
    [
        MDSQ[0][(Q0[(Q0[x[0] as usize] ^ key[4]) as usize] ^ key[0]) as usize],
        MDSQ[1][(Q0[(Q1[x[1] as usize] ^ key[5]) as usize] ^ key[1]) as usize],
        MDSQ[2][(Q1[(Q0[x[2] as usize] ^ key[6]) as usize] ^ key[2]) as usize],
        MDSQ[3][(Q1[(Q1[x[3] as usize] ^ key[7]) as usize] ^ key[3]) as usize],
    ]
}

#[inline(always)]
fn h_192_no_skip(x: [u8; 4], key: &[u8; 12]) -> [u32; 4] {
    h_128_no_skip([
        Q1[x[0] as usize] ^ key[8],
        Q1[x[1] as usize] ^ key[9],
        Q0[x[2] as usize] ^ key[10],
        Q0[x[3] as usize] ^ key[11],
    ], array_ref!(key, 0, 8))
}

#[inline(always)]
fn h_256_no_skip(x: [u8; 4], key: &[u8; 16]) -> [u32; 4] {
    h_192_no_skip([
        Q1[x[0] as usize] ^ key[12],
        Q0[x[1] as usize] ^ key[13],
        Q0[x[2] as usize] ^ key[14],
        Q1[x[3] as usize] ^ key[15],
    ], array_ref!(key, 0, 12))
}

fn g(s: &[[u32; 256]; 4], input: u32) -> u32 {
    let bytes = input.to_le_bytes();
    s[0][bytes[0] as usize] ^ s[1][bytes[1] as usize] ^
        s[2][bytes[2] as usize]^ s[3][bytes[3] as usize]
}

macro_rules! f {
    ($r0:path, $r1:path, $round:expr, $f0:path, $f1:path, $s:expr, $k:expr) => {
        let t0 = g($s, $r0);
        let t1 = g($s, $r1.rotate_left(8));
        $f0 = t0.wrapping_add(t1).wrapping_add($k[$round]);
        $f1 = t0.wrapping_add(t1 << 1).wrapping_add($k[$round+1]);
    }
}

fn rs_mul_column(a: u8, b: u8, c: u8, d: u8, s: &mut [u8; 4], key_byte: u8) {
    if key_byte != 0 {
        let exp = RS_POLY_TO_EXP[(key_byte-1) as usize] as u32;
        s[0] ^= RS_POLY_FROM_EXP[(exp + a as u32) as usize];
        s[1] ^= RS_POLY_FROM_EXP[(exp + b as u32) as usize];
        s[2] ^= RS_POLY_FROM_EXP[(exp + c as u32) as usize];
        s[3] ^= RS_POLY_FROM_EXP[(exp + d as u32) as usize];
    }
}

macro_rules! define_twofish_new {
    ($key_bits:expr, $hfunc:path, $hnoskipfunc:path, $key:expr) => {{
        const KEY_BYTES: usize = $key_bits / 8;
        const KEY_CHUNKS: usize = $key_bits / 64;
        let mut s = [0u8; KEY_CHUNKS*4];
        for i in 0 .. KEY_CHUNKS {
            let off = (KEY_CHUNKS-i-1)*4;
            let s = array_mut_ref!(s, off, 4);
            for column in 0 .. 8 {
                let m = array_ref!(RS_MATRIX, column*4, 4);
                rs_mul_column(m[0], m[1], m[2], m[3], s, $key[i*8+column]);
            }
        }
        let mut sboxen = [[0u32; 256]; 4];
        for x in 0 ..= 255 {
            let rows = $hnoskipfunc(splat(x), &s);
            sboxen[0][x as usize] = rows[0];
            sboxen[1][x as usize] = rows[1];
            sboxen[2][x as usize] = rows[2];
            sboxen[3][x as usize] = rows[3];
        }
        let mut w = [0u32; 8];
        for i in 0..4 {
            let a = $hfunc(splat(2*i), array_ref!($key, 0, KEY_BYTES-4));
            let a = unsplat(&a);
            let b = $hfunc(splat(2*i+1), array_ref!($key, 4, KEY_BYTES-4));
            let b = unsplat(&b).rotate_left(8);
            w[(i*2) as usize] = a.wrapping_add(b);
            w[(i*2+1) as usize]
                = a.wrapping_add(b << 1).rotate_left(9);
        }
        let mut k = [0u32; 32];
        for i in 0..16 {
            let a = $hfunc(splat(2*i+8), array_ref!($key, 0, KEY_BYTES-4));
            let a = unsplat(&a);
            let b = $hfunc(splat(2*i+9), array_ref!($key, 4, KEY_BYTES-4));
            let b = unsplat(&b).rotate_left(8);
            k[(i*2) as usize] = a.wrapping_add(b);
            k[(i*2+1) as usize]
                = a.wrapping_add(b << 1).rotate_left(9);
        }
        Twofish { s: sboxen, w, k }
    }}
}

impl Twofish {
    /// Set up a context to en-/decrypt with a given 128-bit key.
    pub fn new128(key: &[u8; 16]) -> Twofish {
        define_twofish_new!(128, h_128, h_128_no_skip, key)
    }
    /// Set up a context to en-/decrypt with a given 192-bit key.
    pub fn new192(key: &[u8; 24]) -> Twofish {
        define_twofish_new!(192, h_192, h_192_no_skip, key)
    }
    /// Set up a context to en-/decrypt with a given 256-bit key.
    pub fn new256(key: &[u8; 32]) -> Twofish {
        define_twofish_new!(256, h_256, h_256_no_skip, key)
    }
    /// Encrypt a single block.
    pub fn encrypt(&self, i: &[u8; 16], o: &mut [u8; 16]) {
        // whiten input
        let mut r0 = u32::from_le_bytes(*array_ref!(i, 0, 4)) ^ self.w[0];
        let mut r1 = u32::from_le_bytes(*array_ref!(i, 4, 4)) ^ self.w[1];
        let mut r2 = u32::from_le_bytes(*array_ref!(i, 8, 4)) ^ self.w[2];
        let mut r3 = u32::from_le_bytes(*array_ref!(i, 12, 4)) ^ self.w[3];
        // round and round and round we go!
        for round in (0 .. 32).step_by(4) {
            let mut fr0;
            let mut fr1;
            f!(r0, r1, round, fr0, fr1, &self.s, &self.k);
            r2 = (r2^fr0).rotate_right(1);
            r3 = r3.rotate_left(1)^fr1;
            f!(r2, r3, round+2, fr0, fr1, &self.s, &self.k);
            r0 = (r0^fr0).rotate_right(1);
            r1 = r1.rotate_left(1)^fr1;
        }
        // whiten output and ... output it
        o[0..4].copy_from_slice(&(r2^self.w[4]).to_le_bytes()[..]);
        o[4..8].copy_from_slice(&(r3^self.w[5]).to_le_bytes()[..]);
        o[8..12].copy_from_slice(&(r0^self.w[6]).to_le_bytes()[..]);
        o[12..16].copy_from_slice(&(r1^self.w[7]).to_le_bytes()[..]);
    }
    /// Decrypt a single block.
    pub fn decrypt(&self, i: &[u8; 16], o: &mut [u8; 16]) {
        // whiten input
        let mut r2 = u32::from_le_bytes(*array_ref!(i, 0, 4)) ^ self.w[4];
        let mut r3 = u32::from_le_bytes(*array_ref!(i, 4, 4)) ^ self.w[5];
        let mut r0 = u32::from_le_bytes(*array_ref!(i, 8, 4)) ^ self.w[6];
        let mut r1 = u32::from_le_bytes(*array_ref!(i, 12, 4)) ^ self.w[7];
        // og ew dnuor dna dnuor dna dnuor!
        for round in (0 .. 32).step_by(4).rev() {
            let mut fr0;
            let mut fr1;
            f!(r2, r3, round+2, fr0, fr1, &self.s, &self.k);
            r0 = r0.rotate_left(1) ^ fr0;
            r1 = (r1^fr1).rotate_right(1);
            f!(r0, r1, round, fr0, fr1, &self.s, &self.k);
            r2 = r2.rotate_left(1) ^ fr0;
            r3 = (r3^fr1).rotate_right(1);
        }
        o[0..4].copy_from_slice(&(r0^self.w[0]).to_le_bytes()[..]);
        o[4..8].copy_from_slice(&(r1^self.w[1]).to_le_bytes()[..]);
        o[8..12].copy_from_slice(&(r2^self.w[2]).to_le_bytes()[..]);
        o[12..16].copy_from_slice(&(r3^self.w[3]).to_le_bytes()[..]);
    }
}

impl std::fmt::Debug for Twofish {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(fmt, "Twofish {{ ... }}")
    }
}

#[cfg(test)]
mod tests;
