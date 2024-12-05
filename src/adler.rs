use {crate::*, miniunchecked::*, miniunsigned::*};

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

pub struct HashAdler<H, W> {
    a: H,
    b: H,
    window_mod_prime: H,
    #[cfg(debug_assertions)]
    window: W,
    #[cfg(not(debug_assertions))]
    _marker: std::marker::PhantomData<W>,
}

impl<H, W> HashAdler<H, W>
where
    H: AdlerHash,
    W: NonZero,
{
    fn new(window: W) -> Self {
        let window_mod_prime = unsafe {
            H::from(window.get().to_usize() % H::PRIME.to_usize())
                .unwrap_unchecked_dbg_msg("`window` modulo `H::PRIME` should fit into `H::BITS`")
        };

        Self {
            a: H::one(),
            b: H::zero(),
            window_mod_prime,
            #[cfg(debug_assertions)]
            window,
            #[cfg(not(debug_assertions))]
            _marker: Default::default(),
        }
    }

    fn hash_bytes(&mut self, bytes: &[u8]) {
        #[cfg(debug_assertions)]
        {
            let bytes = bytes.len();
            let window = self.window.get().to_usize();
            debug_assert_eq!(
                bytes,
                window,
                "passed in `bytes` slice (length {bytes}) must be equal in size to the `window` (size {window}) the hasher was initialized with"
            );
        }

        match bytes {
            [] => { /* should not be reachable in practice */ }
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

        // https://stackoverflow.com/a/40986904, except
        // - adding two primes for `a` to support 16-bit hash, which could underflow with only one prime added
        // - using window size modulo prime instead of just window size to prevent overflow, as described in the comment
        self.a = (self.a + H::PRIME + H::PRIME + new_byte - old_byte) % H::PRIME;
        self.b = (self.b
            + (H::one() + (self.window_mod_prime * old_byte / H::PRIME)) * H::PRIME
            + self.a
            - (self.window_mod_prime * old_byte)
            - H::one())
            % H::PRIME;
    }

    fn hash(&self) -> H {
        let half_bits = (H::BITS / 2) as _;
        let mask = H::max_value() >> half_bits;
        (self.b << half_bits) | (self.a & mask)
    }

    fn byte(byte: u8) -> H {
        <H as Unsigned>::from_u8(byte)
    }
}

impl<H, W> RollingHashImpl<H, W> for HashAdler<H, W>
where
    H: AdlerHash,
    W: NonZero,
{
    fn new(window: W) -> Self {
        Self::new(window)
    }

    fn hash_bytes(&mut self, bytes: &[u8]) {
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
    use {
        super::*,
        rand::{distributions::Distribution, Rng, SeedableRng},
    };

    // Compare the 32bit hash to the reference implementation in the [`adler32`](https://crates.io/crates/adler32) crate.
    fn roll_test_impl(bytes: &[u8], window: NonZeroU32) {
        assert!(bytes.len().to_usize() >= window.get().to_usize());

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

    #[test]
    fn adler32_test_small() {
        let bytes = &[0u8, 1, 2, 3, 4, 5, 6, 7];
        let window = NonZeroU32::new(4).unwrap();

        roll_test_impl(bytes, window);
    }

    const NUM_RANDOM_ITERATIONS: usize = 10;

    fn generate_random_bytes<R: Rng>(rng: &mut R, size: usize) -> Vec<u8> {
        use rand::distributions::Uniform;

        let random_byte_distr = Uniform::new_inclusive(0u8, u8::MAX);

        (0..size).map(|_| random_byte_distr.sample(rng)).collect()
    }

    #[test]
    fn adler32_test_random() {
        let window = NonZeroU32::new(256).unwrap();

        for i in 0..NUM_RANDOM_ITERATIONS {
            let mut rng = rand::rngs::SmallRng::seed_from_u64(i as _);

            let bytes = generate_random_bytes(&mut rng, u16::MAX as usize + 1);

            roll_test_impl(&bytes, window);
        }
    }
}
