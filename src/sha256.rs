//! An implementation of the [SHA-256][1] cryptographic hash function, in both
//! buffered and unbuffered flavors. Enabled by default, or if you request the
//! `"sha256"` feature.
//!
//! Use [`hash()`][2] if the data you're hashing is already present in
//! contiguous memory, [`RawSha256`][3] if it is convenient for you to provide
//! data in 64-byte blocks, or [`BufSha256`][4] otherwise.
//!
//! [1]: https://en.wikipedia.org/wiki/SHA-2
//! [2]: fn.hash.html
//! [3]: struct.RawSha256.html
//! [4]: struct.BufSha256.html

/// The number of bytes in a SHA-256 hash. (256 bits = 32 bytes)
pub const HASHBYTES: usize = 32;
/// The number of bytes consumed in each "round" of SHA-256. (512 bits = 64
/// bytes)
pub const BLOCKBYTES: usize = 64;

const K: [u32; 64] = [
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
  0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
  0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
  0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
  0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
  0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// A raw SHA-256 state. This does not include a buffer, so you must provide
/// data in exact increments of `BLOCKBYTES` (64 bytes).
///
/// ```rust
/// # use lsx::sha256;
/// # use sha256::RawSha256;
/// const DATA: &[u8] = b"Lorem ipsum dolor sit amet, consectetur adipisicing \
///                       elit, sed do eiusmod tempor incididunt ut labore et \
///                       dolore magna aliqua. Ut enim ad minim veniam, quis \
///                       nostrud exercitation ullamco laboris nisi ut \
///                       aliquip ex ea commodo consequat. Duis aute irure \
///                       dolor in reprehenderit in voluptate velit esse \
///                       cillum dolore eu fugiat nulla pariatur. Excepteur \
///                       sint occaecat cupidatat non proident, sunt in culpa \
///                       qui officia deserunt mollit anim id est laborum.";
/// let mut hasher = RawSha256::new();
/// hasher.update(&DATA[.. sha256::BLOCKBYTES]);
/// // you can provide more than one block (this next call provides two)
/// hasher.update(&DATA[sha256::BLOCKBYTES .. sha256::BLOCKBYTES * 3]);
/// // empty blocks have no effect
/// hasher.update(&[]);
/// // finish can handle more than one block if needed
/// assert_eq!(hasher.finish(&DATA[sha256::BLOCKBYTES * 3 ..]),
///            [0x2c,0x7c,0x3d,0x5f,0x24,0x4f,0x1a,0x40,0x06,0x9a,0x32,0x22,
///             0x42,0x15,0xe0,0xcf,0x9b,0x42,0x48,0x5c,0x99,0xd8,0x0f,0x35,
///             0x7d,0x76,0xf0,0x06,0x35,0x9c,0x7a,0x18]);
/// ```

#[derive(Copy,Clone)]
pub struct RawSha256 {
    h: [u32; 8],
    byte_count: u64,
}

/// A SHA-256 state, including a buffer to allow non-block-sized inputs.
///
/// ```rust
/// # use lsx::sha256::BufSha256;
/// const DATA_1: &[u8] = b"Here is a piece of text that is not exactly 64 \
///                         characters.";
/// const DATA_2: &[u8] = b"Here is another piece of text that's not \
///                         contiguous in memory with the other one.";
/// const DATA_3: &[u8] = b"Have a little more text!";
/// let mut hasher = BufSha256::new();
/// hasher.update(DATA_1);
/// hasher.update(DATA_2);
/// let hash1 = hasher.finish(DATA_3);
/// assert_eq!(hash1,
///            [0xa7,0x15,0xf7,0x84,0xb9,0xb3,0xd7,0x45,0x15,0x9f,0xe7,0x5f,
///             0xfa,0xab,0xaa,0xf9,0xf3,0x9c,0xa6,0x44,0x29,0xa6,0xd6,0x34,
///             0x86,0x66,0x2a,0x1f,0x0b,0xce,0xbd,0xdb]);
/// // You can also provide an empty slice when finishing
/// let mut hasher = BufSha256::new();
/// hasher.update(DATA_1);
/// hasher.update(DATA_2);
/// hasher.update(DATA_3);
/// let hash2 = hasher.finish(&[]);
/// assert_eq!(hash1, hash2);
/// ```
#[derive(Copy,Clone)]
pub struct BufSha256 {
    inner: RawSha256,
    buf: [u8; BLOCKBYTES],
    buffered_bytes: u32,
}

impl RawSha256 {
    /// Start a new hash.
    pub fn new() -> RawSha256 {
        RawSha256 {
            h: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
            ],
            byte_count: 0,
        }
    }
    /// Perform a single round of SHA-256.
    fn round(&mut self, input: &[u8; BLOCKBYTES]) {
        let mut a = self.h[0];
        let mut b = self.h[1];
        let mut c = self.h[2];
        let mut d = self.h[3];
        let mut e = self.h[4];
        let mut f = self.h[5];
        let mut g = self.h[6];
        let mut h = self.h[7];
        let mut w = [0u32; 64];
        for n in 0..16 {
            let inblock = array_ref![input, n*4, 4];
            w[n] = u32::from_be_bytes(*inblock);
        }
        for n in 16..64 {
            let s0 = w[n-15].rotate_right(7) ^ w[n-15].rotate_right(18)
                ^ (w[n-15]>>3);
            let s1 = w[n-2].rotate_right(17) ^ w[n-2].rotate_right(19)
                ^ (w[n-2]>>10);
            w[n] = w[n-16].wrapping_add(s0)
                .wrapping_add(w[n-7]).wrapping_add(s1);
        }
        for n in 0..64 {
            let s1 = (e.rotate_right(6) ^ e.rotate_right(11)
                      ^ e.rotate_right(25)).wrapping_add(h)
                .wrapping_add((e&f)^(!e&g)).wrapping_add(K[n])
                .wrapping_add(w[n]);
            let s0 = (a.rotate_right(2) ^ a.rotate_right(13)
                      ^ a.rotate_right(22)).wrapping_add((a&b)^(a&c)^(b&c));
            h = g; g = f; f = e; e = d.wrapping_add(s1);
            d = c; c = b; b = a; a = s0.wrapping_add(s1);
        }
        self.h[0] = self.h[0].wrapping_add(a);
        self.h[1] = self.h[1].wrapping_add(b);
        self.h[2] = self.h[2].wrapping_add(c);
        self.h[3] = self.h[3].wrapping_add(d);
        self.h[4] = self.h[4].wrapping_add(e);
        self.h[5] = self.h[5].wrapping_add(f);
        self.h[6] = self.h[6].wrapping_add(g);
        self.h[7] = self.h[7].wrapping_add(h);
    }
    /// Process some blocks of data. Panics if the input is not an exact
    /// multiple of `BLOCKBYTES` (64 bytes).
    pub fn update(&mut self, data: &[u8]) {
        assert_eq!(data.len() % BLOCKBYTES, 0);
        for chunk in data.chunks_exact(BLOCKBYTES) {
            self.round(array_ref!(chunk, 0, BLOCKBYTES));
        }
        self.byte_count = self.byte_count.checked_add(data.len() as u64)
            .expect("cannot hash more than 2^61 bytes at a go");
    }
    /// Process the remaining data and produce a finished hash. The input does
    /// *not* need to be a multiple of `BLOCKBYTES`.
    pub fn finish(mut self, data: &[u8]) -> [u8; HASHBYTES] {
        let data = if data.len() >= BLOCKBYTES {
            let extra = data.len() % BLOCKBYTES;
            self.update(&data[.. data.len()-extra]);
            &data[data.len()-extra ..]
        } else { data };
        let byte_count = self.byte_count.checked_add(data.len() as u64)
            .expect("cannot hash more than 2^61 bytes at a go");
        if byte_count >= 0x2000000000000000 {
            panic!("cannot hash more than 2^61 bytes at a go");
        }
        let mut block = [0u8; BLOCKBYTES*2];
        block[..data.len()].copy_from_slice(data);
        block[data.len()] = 0x80;
        if data.len() > BLOCKBYTES - 9 {
            block[BLOCKBYTES*2-8 .. BLOCKBYTES*2]
                .copy_from_slice(&(byte_count << 3).to_be_bytes()[..]);
            self.round(array_ref!(block, 0, BLOCKBYTES));
            self.round(array_ref!(block, BLOCKBYTES, BLOCKBYTES));
        }
        else {
            block[BLOCKBYTES-8 .. BLOCKBYTES]
                .copy_from_slice(&(byte_count << 3).to_be_bytes()[..]);
            self.round(array_ref!(block, 0, BLOCKBYTES));
        }
        let mut ret = [0u8; HASHBYTES];
        ret[ 0.. 4].copy_from_slice(&self.h[0].to_be_bytes()[..]);
        ret[ 4.. 8].copy_from_slice(&self.h[1].to_be_bytes()[..]);
        ret[ 8..12].copy_from_slice(&self.h[2].to_be_bytes()[..]);
        ret[12..16].copy_from_slice(&self.h[3].to_be_bytes()[..]);
        ret[16..20].copy_from_slice(&self.h[4].to_be_bytes()[..]);
        ret[20..24].copy_from_slice(&self.h[5].to_be_bytes()[..]);
        ret[24..28].copy_from_slice(&self.h[6].to_be_bytes()[..]);
        ret[28..32].copy_from_slice(&self.h[7].to_be_bytes()[..]);
        ret
    }
}

impl BufSha256 {
    /// Initialize a SHA-256 state.
    pub fn new() -> BufSha256 {
        BufSha256 {
            inner: RawSha256::new(),
            buf: [0u8; BLOCKBYTES],
            buffered_bytes: 0,
        }
    }
    /// Process some data. You may provide any amount of data you wish.
    pub fn update(&mut self, mut data: &[u8]) {
        if self.buffered_bytes > 0 {
            let remaining_bytes = BLOCKBYTES - (self.buffered_bytes as usize);
            if remaining_bytes <= data.len() {
                self.buf[self.buffered_bytes as usize ..]
                    .copy_from_slice(&data[.. remaining_bytes]);
                self.inner.update(&self.buf[..]);
                self.buffered_bytes = 0;
                data = &data[remaining_bytes ..];
            }
            else {
                self.buf[self.buffered_bytes as usize ..
                         self.buffered_bytes as usize + data.len()]
                    .copy_from_slice(&data[..]);
                self.buffered_bytes = self.buffered_bytes + data.len() as u32;
                return;
            }
        }
        debug_assert_eq!(self.buffered_bytes, 0);
        if data.len() >= BLOCKBYTES {
            let chop = data.len() - (data.len() % BLOCKBYTES);
            self.inner.update(&data[..chop]);
            data = &data[chop..];
        }
        debug_assert!(data.len() < BLOCKBYTES);
        self.buf[..data.len()].copy_from_slice(data);
        self.buffered_bytes = data.len() as u32;
    }
    /// Process any remaining data and produce a finished hash.
    pub fn finish(mut self, data: &[u8]) -> [u8; HASHBYTES] {
        if data.len() != 0 { self.update(data) }
        self.inner.finish(&self.buf[.. self.buffered_bytes as usize])
    }
}

/// Calculate the SHA-256 hash of a given byte string. Useful if your entire
/// message is already in contiguous memory. If it's not, you should use one
/// of this module's structs instead.
///
/// ```rust
/// # use lsx::sha256;
/// assert_eq!(sha256::hash(b"The quick brown fox jumps over the lazy dog"),
///            [0xd7,0xa8,0xfb,0xb3,0x07,0xd7,0x80,0x94,0x69,0xca,0x9a,0xbc,
///             0xb0,0x08,0x2e,0x4f,0x8d,0x56,0x51,0xe4,0x6d,0x3c,0xdb,0x76,
///             0x2d,0x02,0xd0,0xbf,0x37,0xc9,0xe5,0x92]);
/// ```
pub fn hash(data: &[u8]) -> [u8; HASHBYTES] {
    RawSha256::new().finish(data)
}

#[cfg(test)]
mod tests;

impl std::fmt::Debug for RawSha256 {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(fmt, "RawSha256 {{ ... }}")
    }
}

impl std::fmt::Debug for BufSha256 {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(fmt, "BufSha256 {{ ... }}")
    }
}
