use {crate::*, miniunsigned::*};

// `u16` or `u32`.
pub trait AdlerHash: Unsigned {
    const PRIME: Self;
    const BLOCK_SIZE: usize;
}

impl AdlerHash for u16 {
    // Largest prime smaller than `256` == `u8::MAX + 1`
    const PRIME: Self = 251;

    // The largest `n` such that `255 * n * (n + 1) / 2 + (n + 1) * (PRIME - 1) <= 2^16 - 1`
    const BLOCK_SIZE: usize = 21;
}

impl AdlerHash for u32 {
    // Largest prime smaller than `65536` == `u16::MAX + 1`
    const PRIME: Self = 65521;

    // The largest `n` such that `255 * n * (n + 1) / 2 + (n + 1) * (PRIME - 1) <= 2^32 - 1`
    const BLOCK_SIZE: usize = 5552;
}

pub struct HashAdler<H, S, W> {
    a: H,
    b: H,
    window_truncated: H,
    #[cfg(debug_assertions)]
    window: W,
    #[cfg(debug_assertions)]
    _marker: std::marker::PhantomData<S>,
    #[cfg(not(debug_assertions))]
    _marker: std::marker::PhantomData<(S, W)>,
}

impl<H, S, W> HashAdler<H, S, W>
where
    H: AdlerHash,
    S: Unsigned,
    W: NonZero<S>,
{
    fn new(window: W) -> Self {
        // Truncate `window` to `H::BITS` bits for `wrapping_sub()` purposes in `remove_byte()`.
        let window_truncated = unsafe {
            H::from_usize(window.get().to_usize() & H::max_value().to_usize())
                .unwrap_unchecked_dbg_msg("`window` truncation to `H` bits must succeed")
        };

        Self {
            a: H::one(),
            b: H::zero(),
            window_truncated,
            #[cfg(debug_assertions)]
            window,
            _marker: Default::default(),
        }
    }

    fn hash_bytes(&mut self, bytes: &[u8]) {
        match bytes {
            [] => {}
            [byte] => {
                self.a = (self.a + Self::byte(*byte)) % H::PRIME;
                self.b = (self.b + self.a) % H::PRIME;
            }
            [bytes @ ..] => {
                let mut hash_block = |mut bytes: &[u8]| {
                    debug_assert!(bytes.len() <= H::BLOCK_SIZE);

                    while let [byte, rest @ ..] = bytes {
                        self.a += Self::byte(*byte);
                        self.b += self.a;

                        bytes = rest;
                    }

                    self.a = self.a % H::PRIME;
                    self.b = self.b % H::PRIME;
                };

                for block in bytes.chunks(H::BLOCK_SIZE) {
                    hash_block(block);
                }
            }
        }
    }

    fn roll_hash(&mut self, old_byte: u8, new_byte: u8) {
        let old_byte = Self::byte(old_byte);
        let new_byte = Self::byte(new_byte);
        self.a = (self.a + new_byte + H::PRIME - old_byte) % H::PRIME;
        self.b = ((self.b + self.a + H::PRIME - H::one()).wrapping_add(
            &H::PRIME
                .wrapping_sub(&self.window_truncated)
                .wrapping_mul(&old_byte),
        )) % H::PRIME;
    }

    fn hash(&self) -> H {
        let b_offset = (H::BITS / 2) as _;
        (self.b << b_offset) | self.a
    }

    fn byte(byte: u8) -> H {
        <H as Unsigned>::from_u8(byte)
    }
}

impl<H, S, W> RollingHashImpl<H, S, W> for HashAdler<H, S, W>
where
    H: AdlerHash,
    S: Unsigned,
    W: NonZero<S>,
{
    fn new(window: W) -> Self {
        Self::new(window)
    }

    fn hash_bytes(&mut self, bytes: &[u8]) {
        #[cfg(debug_assertions)]
        {
            debug_assert_eq!(bytes.len(), self.window.get().to_usize());
        }

        self.hash_bytes(bytes)
    }

    fn roll_hash(&mut self, old_byte: u8, new_byte: u8) {
        self.roll_hash(old_byte, new_byte);
    }

    fn hash(&self) -> H {
        self.hash()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Compare the 32bit hash to the reference implementation in the [`adler32`](https://crates.io/crates/adler32) crate.
    #[test]
    fn adler32_test() {
        let bytes = [0u8, 1, 2, 3, 4, 5, 6, 7];

        let window = NonZeroU32::new(4).unwrap();

        let hash = RollingHashAdler32::new(&bytes, window);

        let mut hash_reference =
            adler32::RollingAdler32::from_buffer(&bytes[..window.get() as usize]);

        let mut iter = hash.into_iter().enumerate();

        while let Some((offset, hash)) = iter.next() {
            assert_eq!(hash, hash_reference.hash());

            if (offset + window.get() as usize) < bytes.len() {
                let old_byte = bytes[offset];
                let new_byte = bytes[offset + window.get() as usize];
                hash_reference.remove(window.get() as usize, old_byte);
                hash_reference.update(new_byte);
            }
        }
    }
}
