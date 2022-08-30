//! # minirollinghash
//!
//! Provides a couple simple rolling hash iterator wrappers.
//! 16- and 32-bit Adler and cyclic polynomial.

#[cfg(feature = "adler")]
mod adler;

#[cfg(feature = "cyclic_poly")]
mod cyclic_poly;

#[cfg(feature = "adler")]
pub use adler::*;

#[cfg(feature = "cyclic_poly")]
pub use cyclic_poly::*;
use miniunsigned::Unsigned;

use {
    miniunchecked::*,
    miniunsigned::*,
    std::{
        iter::{ExactSizeIterator, Iterator},
        marker::PhantomData,
        num::{NonZeroU16, NonZeroU32},
    },
};

/// An implementation of the rolling hash.
///
/// Needs to know hot to hash the initial byte window of the source byte slice,
/// how to roll the hash given the old and new bytes,
/// and to return the calculated hash.
pub trait RollingHashImpl<H: Unsigned> {
    /// Initialize the rolling hash implementation.
    ///
    /// It will be used to calculate the hashes for `window`-sized windows.
    fn new(window: impl NonZero<H>) -> Self;
    /// Called once by the rolling hash to initialize the hash for the first window of the source byte slice.
    ///
    /// Length of the `bytes` slice is guaranteed to be equal to the window size
    /// the rolling hash implementation was initialized with.
    fn hash_bytes(&mut self, bytes: &[u8]);
    /// Called multiple times by the rolling hash to roll the `window`-sized hash window over the source byte slice.
    ///
    /// `old_byte` is the first byte of the previous window, `new_byte` is the first byte past the end of the previous window.
    fn roll_hash(&mut self, old_byte: u8, new_byte: u8, window: impl NonZero<H>);
    /// Returns the rolling hash implementation's calculated hash value for the current hash window,
    fn hash(&self) -> H;
}

/// Rolling hash (exact size) iterator adapter.
///
/// Returns hashes of consecutive complete `window`-byte-sized windows of the `bytes` slice,
/// until the last `window` bytes of the slice.
pub struct RollingHash<'a, H, W, R> {
    bytes: &'a [u8],
    window: W,
    hash: R,
    offset: usize,
    _marker: PhantomData<H>,
}

impl<'a, H, W, R> RollingHash<'a, H, W, R>
where
    H: Unsigned,
    W: NonZero<H>,
    R: RollingHashImpl<H>,
{
    /// Creates the rolling hash (exact size) iterator adapter.
    ///
    /// Returns hashes of consecutive complete `window`-byte-sized windows of the `bytes` slice,
    /// until the last `window` bytes of the slice.
    ///
    /// The iterator will be empty if `bytes` is not at least `window` bytes long.
    pub fn new(bytes: &'a [u8], window: W) -> Self {
        Self {
            bytes,
            window,
            hash: R::new(window),
            offset: 0,
            _marker: PhantomData,
        }
    }

    /// Convenience method to hash the entire `bytes` slice using this rolling hash implementation.
    ///
    /// Returns `None` if `bytes` is emtpy or longer than maximum window size (i.e. window size type's maximum value).
    pub fn hash_bytes(bytes: &[u8]) -> Option<H> {
        let window = W::new(H::from_usize(bytes.len())?)?;
        let mut hash = R::new(window);
        hash.hash_bytes(bytes);
        Some(hash.hash())
    }

    fn len(&self) -> usize {
        self.bytes
            .len()
            .saturating_sub(self.window() - 1 + self.offset)
    }

    fn window(&self) -> usize {
        self.window.get().to_usize()
    }
}

impl<'a, H, W, R> Iterator for RollingHash<'a, H, W, R>
where
    H: Unsigned,
    W: NonZero<H>,
    R: RollingHashImpl<H>,
{
    type Item = H;

    fn next(&mut self) -> Option<Self::Item> {
        let offset = self.offset;
        self.offset += 1;
        if offset == 0 {
            self.hash.hash_bytes(self.bytes.get(..self.window())?);
            return Some(self.hash.hash());
        } else {
            let new_byte = *self.bytes.get(offset - 1 + self.window())?;
            let old_byte = *unsafe { self.bytes.get_unchecked(offset - 1) };
            self.hash.roll_hash(old_byte, new_byte, self.window);
            return Some(self.hash.hash());
        }
    }
}

impl<'a, H, W, T> ExactSizeIterator for RollingHash<'a, H, W, T>
where
    H: Unsigned,
    W: NonZero<H>,
    T: RollingHashImpl<H>,
{
    fn len(&self) -> usize {
        self.len()
    }
}

#[cfg(feature = "adler")]
pub type RollingHashAdler<'a, H, W> = RollingHash<'a, H, W, HashAdler<H>>;
#[cfg(feature = "cyclic_poly")]
pub type RollingHashCyclicPoly<'a, H, W> = RollingHash<'a, H, W, HashCyclicPoly<H>>;

/// 16-bit Adler rolling hash.
#[cfg(feature = "adler")]
pub type RollingHashAdler16<'a> = RollingHashAdler<'a, u16, NonZeroU16>;
/// 32-bit Adler rolling hash.
#[cfg(feature = "adler")]
pub type RollingHashAdler32<'a> = RollingHashAdler<'a, u32, NonZeroU32>;

/// 16-bit cyclic polynomial rolling hash.
#[cfg(feature = "cyclic_poly")]
pub type RollingHashCyclicPoly16<'a> = RollingHashCyclicPoly<'a, u16, NonZeroU16>;
/// 32-bit cyclic polynomial rolling hash.
#[cfg(feature = "cyclic_poly")]
pub type RollingHashCyclicPoly32<'a> = RollingHashCyclicPoly<'a, u32, NonZeroU32>;

#[cfg(test)]
mod tests {
    use super::*;

    // Tests that the rolling hash is equal to the value calculated from the window directly.
    fn roll_test_impl<H, W, R>(bytes: &[u8], window: W)
    where
        H: Unsigned + std::fmt::Debug,
        W: NonZero<H>,
        R: RollingHashImpl<H>,
    {
        assert!(!bytes.is_empty());

        let hash = RollingHash::<'_, H, W, R>::new(bytes, window);

        let initial_len = bytes.len() - window.get().to_usize() + 1;
        assert_eq!(hash.len(), initial_len);

        let hash_bytes = |bytes: &[u8]| {
            let mut hash = R::new(window);
            hash.hash_bytes(bytes);
            hash.hash()
        };

        let mut iter = hash.into_iter().enumerate();

        while let Some((offset, hash)) = iter.next() {
            let window = &bytes[offset..offset + window.get().to_usize()];
            assert_eq!(hash, hash_bytes(window));

            // `-1` to account for the returned item above.
            assert_eq!(iter.len(), initial_len - offset - 1);
        }
    }

    #[cfg(any(feature = "adler", feature = "cyclic_poly"))]
    #[test]
    fn roll_test() {
        let bytes = [0u8, 1, 2, 3, 4, 5, 6, 7];

        #[cfg(feature = "adler")]
        {
            roll_test_impl::<u16, NonZeroU16, adler::HashAdler<u16>>(
                &bytes,
                NonZeroU16::new(4).unwrap(),
            );
            roll_test_impl::<u32, NonZeroU32, adler::HashAdler<u32>>(
                &bytes,
                NonZeroU32::new(4).unwrap(),
            );
        }

        #[cfg(feature = "cyclic_poly")]
        {
            roll_test_impl::<u16, NonZeroU16, cyclic_poly::HashCyclicPoly<u16>>(
                &bytes,
                NonZeroU16::new(4).unwrap(),
            );
            roll_test_impl::<u32, NonZeroU32, cyclic_poly::HashCyclicPoly<u32>>(
                &bytes,
                NonZeroU32::new(4).unwrap(),
            );
        }
    }
}
