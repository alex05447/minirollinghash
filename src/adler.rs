use {crate::*, miniunsigned::*};

// `u16` or `u32`.
pub trait AdlerHash: Unsigned {
    const PRIME: Self;
}

impl AdlerHash for u16 {
    // Largest prime smaller than `256` == `u8::MAX + 1`
    const PRIME: Self = 251;
}

impl AdlerHash for u32 {
    // Largest prime smaller than `65536` == `u16::MAX + 1`
    const PRIME: Self = 65521;
}

pub struct HashAdler<H, W> {
    a: H,
    b: H,
    window: W,
}

impl<H: AdlerHash, W: NonZero<H>> HashAdler<H, W> {
    fn new(window: W) -> Self {
        Self {
            a: H::one(),
            b: H::zero(),
            window,
        }
    }

    fn hash_bytes(&mut self, bytes: &[u8]) {
        for &byte in bytes {
            self.a = self.a + <H as Unsigned>::from_u8(byte);
            self.b = self.b + self.a;
        }
        if self.a >= H::PRIME {
            self.a = self.a - H::PRIME;
        }
        self.b = self.b % H::PRIME;
    }

    fn hash_byte(&mut self, byte: u8) {
        self.a = (self.a + <H as Unsigned>::from_u8(byte)) % H::PRIME;
        self.b = (self.b + self.a) % H::PRIME;
    }

    fn remove_byte(&mut self, byte: u8) {
        let byte = <H as Unsigned>::from_u8(byte);
        self.a = (self.a + H::PRIME - byte) % H::PRIME;
        self.b = ((self.b + H::PRIME - H::one()).wrapping_add(
            &H::PRIME
                .wrapping_sub(&self.window.get())
                .wrapping_mul(&byte),
        )) % H::PRIME;
    }

    fn get_hash(&self) -> H {
        const NUM_BITS_IN_BYTE: usize = 8;
        let num_bits_in_hash = std::mem::size_of::<H>() * NUM_BITS_IN_BYTE;
        let b_offset = num_bits_in_hash / 2;
        (self.b << b_offset) | self.a
    }
}

impl<H: AdlerHash, W: NonZero<H>> RollingHashImpl<H, W> for HashAdler<H, W> {
    fn new(window: W) -> Self {
        Self::new(window)
    }

    fn hash_bytes(&mut self, bytes: &[u8]) {
        debug_assert_eq!(bytes.len(), self.window.get().to_usize());

        self.hash_bytes(bytes)
    }

    fn roll_hash(&mut self, old_byte: u8, new_byte: u8) {
        self.remove_byte(old_byte);
        self.hash_byte(new_byte);
    }

    fn hash(&self) -> H {
        self.get_hash()
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
