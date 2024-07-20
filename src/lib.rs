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

use {
    miniunsigned::*,
    std::{
        iter::{ExactSizeIterator, FusedIterator, Iterator},
        marker::PhantomData,
        slice::Windows,
    },
};

#[cfg(any(feature = "adler", feature = "cyclic_poly"))]
use std::num::{NonZeroU16, NonZeroU32};

/// An implementation of the rolling hash.
///
/// Needs to know how to hash the initial byte window of the source byte slice,
/// how to roll the hash window given the old and new bytes,
/// and needs to return the calculated hash.
///
/// `H` - type of the returned hash.
/// `S` - raw type for the size of the rolling hash window.
/// `W` - non-zero type for the size of the rolling hash window.
pub trait RollingHashImpl<H, S, W>
where
    H: Unsigned,
    S: Unsigned,
    W: NonZero<S>,
{
    /// Initialize the rolling hash implementation.
    ///
    /// It will be used to calculate the hashes for `window`-sized byte slice windows.
    fn new(window: W) -> Self;

    /// Called once by the rolling hash to initialize the hash for the first window of the source byte slice.
    ///
    /// NOTE - length of the `bytes` must be equal to the window size
    /// the rolling hash implementation was initialized with.
    fn hash_bytes(&mut self, bytes: &[u8]);

    /// Called multiple times by the rolling hash to roll the `window`-sized hash window over the source byte slice.
    ///
    /// `old_byte` is the first byte of the previous window, `new_byte` is the first byte past the end of the previous window.
    fn roll_hash(&mut self, old_byte: u8, new_byte: u8);

    /// Returns the rolling hash implementation's calculated hash value for the current hash window.
    fn hash(&self) -> H;
}

/// Rolling hash iterator adapter.
///
/// Returns the hashes of consecutive complete windows of the hashed slice.
pub struct RollingHash<'a, H, S, W, R> {
    /// Source slice to hash as its windows iterator.
    windows: Option<Windows<'a, u8>>,
    /// Byte to roll off when processing the non-first windows.
    old_byte: Option<u8>,
    /// Rolling hash implementation to use.
    hash: R,
    _marker: PhantomData<(H, S, W)>,
}

impl<'a, H, S, W, R> RollingHash<'a, H, S, W, R>
where
    H: Unsigned,
    S: Unsigned,
    W: NonZero<S>,
    R: RollingHashImpl<H, S, W>,
{
    /// Creates the rolling hash iterator adapter.
    ///
    /// Returns the hashes of consecutive complete `window`-byte-sized windows of the hashed `bytes` slice.
    ///
    /// The iterator will be empty if `bytes` is not at least `window` bytes long.
    pub fn new(bytes: &'a [u8], window: W) -> Self {
        let window_usize = window.get().to_usize();
        Self {
            windows: (bytes.len() >= window_usize).then_some(bytes.windows(window_usize)),
            old_byte: None,
            hash: R::new(window),
            _marker: PhantomData,
        }
    }

    /// Convenience method to hash the entire `bytes` slice using this rolling hash implementation.
    ///
    /// Returns `None` if `bytes` is emtpy or longer than maximum window size (i.e. window size type's maximum value).
    pub fn hash_bytes(bytes: &[u8]) -> Option<H> {
        let window = W::new(S::from_usize(bytes.len())?)?;
        let mut hash = R::new(window);
        hash.hash_bytes(bytes);
        Some(hash.hash())
    }

    fn len(&self) -> usize {
        self.windows.as_ref().map(Windows::len).unwrap_or(0)
    }
}

impl<'a, H, S, W, R> Iterator for RollingHash<'a, H, S, W, R>
where
    H: Unsigned,
    S: Unsigned,
    W: NonZero<S>,
    R: RollingHashImpl<H, S, W>,
{
    type Item = H;

    fn next(&mut self) -> Option<Self::Item> {
        self.windows.as_mut()?.next().map(|window| {
            if let Some(old_byte) = self.old_byte {
                // This is not the first window - roll off the old byte from the previous window,
                // roll on the new byte from the current window.
                let new_byte = *window.last().unwrap();
                self.hash.roll_hash(old_byte, new_byte);
            } else {
                // This is the first window - hash the entire window.
                self.hash.hash_bytes(window);
            }

            // Update the byte to be rolled off on the next iteration.
            self.old_byte.replace(*window.first().unwrap());

            // Return the current window's hash.
            self.hash.hash()
        })
    }
}

impl<'a, H, S, W, T> ExactSizeIterator for RollingHash<'a, H, S, W, T>
where
    H: Unsigned,
    S: Unsigned,
    W: NonZero<S>,
    T: RollingHashImpl<H, S, W>,
{
    fn len(&self) -> usize {
        self.len()
    }
}

impl<'a, H, S, W, T> FusedIterator for RollingHash<'a, H, S, W, T>
where
    H: Unsigned,
    S: Unsigned,
    W: NonZero<S>,
    T: RollingHashImpl<H, S, W>,
{
}

#[cfg(feature = "adler")]
pub type RollingHashAdler<'a, H, S, W> = RollingHash<'a, H, S, W, HashAdler<H, S, W>>;
#[cfg(feature = "cyclic_poly")]
pub type RollingHashCyclicPoly<'a, H, S, W> = RollingHash<'a, H, S, W, HashCyclicPoly<H, S, W>>;

/// 16-bit Adler rolling hash.
#[cfg(feature = "adler")]
pub type RollingHashAdler16<'a> = RollingHashAdler<'a, u16, u16, NonZeroU16>;
/// 32-bit Adler rolling hash.
#[cfg(feature = "adler")]
pub type RollingHashAdler32<'a> = RollingHashAdler<'a, u32, u32, NonZeroU32>;

/// 16-bit cyclic polynomial rolling hash.
#[cfg(feature = "cyclic_poly")]
pub type RollingHashCyclicPoly16<'a> = RollingHashCyclicPoly<'a, u16, u16, NonZeroU16>;
/// 32-bit cyclic polynomial rolling hash.
#[cfg(feature = "cyclic_poly")]
pub type RollingHashCyclicPoly32<'a> = RollingHashCyclicPoly<'a, u32, u32, NonZeroU32>;

#[cfg(test)]
#[cfg(any(feature = "adler", feature = "cyclic_poly"))]
mod tests {
    use {
        super::*,
        rand::{distributions::Distribution, Rng, SeedableRng},
    };

    // Tests that the rolling hash processes slices of at least `window` bytes size.
    fn slice_too_short_test_impl<H, S, W, R>(bytes: &[u8], window: W)
    where
        H: Unsigned + std::fmt::Debug,
        S: Unsigned,
        W: NonZero<S>,
        R: RollingHashImpl<H, S, W>,
    {
        assert!(bytes.len() < window.get().to_usize());

        let mut hash = RollingHash::<'_, H, S, W, R>::new(bytes, window);

        assert_eq!(hash.len(), 0);

        assert!(hash.next().is_none());
    }

    // Tests that the rolling hash is equal to the value calculated from the window directly.
    fn roll_test_impl<H, S, W, R>(bytes: &[u8], window: W)
    where
        H: Unsigned + std::fmt::Debug,
        S: Unsigned,
        W: NonZero<S>,
        R: RollingHashImpl<H, S, W>,
    {
        assert!(bytes.len() >= window.get().to_usize());

        let hash = RollingHash::<'_, H, S, W, R>::new(bytes, window);

        let hash_len = bytes.len() - window.get().to_usize() + 1;
        assert_eq!(hash.len(), hash_len);

        let mut iter = hash.into_iter().enumerate();
        assert_eq!(iter.len(), hash_len);

        while let Some((offset, hash)) = iter.next() {
            let window = &bytes[offset..offset + window.get().to_usize()];
            assert_eq!(
                hash,
                RollingHash::<'_, H, S, W, R>::hash_bytes(window).unwrap()
            );

            // `-1` to account for the returned item above.
            assert_eq!(iter.len(), hash_len - offset - 1);
        }

        assert_eq!(iter.len(), 0);
        assert!(iter.next().is_none());
    }

    const NUM_RANDOM_ITERATIONS: usize = 10;

    fn generate_random_bytes<R: Rng>(rng: &mut R, size: usize) -> Vec<u8> {
        use rand::distributions::Uniform;

        let random_byte_distr = Uniform::new_inclusive(0u8, u8::MAX);

        (0..size).map(|_| random_byte_distr.sample(rng)).collect()
    }

    fn generate_duplicate_windows<R: Rng, S: Unsigned, W: NonZero<S>>(
        rng: &mut R,
        bytes: &mut [u8],
        window_size: W,
    ) -> Option<Vec<usize>> {
        use rand::distributions::Uniform;

        let window_size = window_size.get().to_usize();
        assert!(bytes.len() >= window_size);

        let duplicate_window_fraction = 8;
        let min_num_duplicate_windows = 2;
        let max_num_duplicate_windows = 64;

        let num_duplicate_windows =
            (bytes.len() / window_size / duplicate_window_fraction).min(max_num_duplicate_windows);

        if num_duplicate_windows < min_num_duplicate_windows {
            return None;
        }

        let num_windows =
            Uniform::new_inclusive(min_num_duplicate_windows, num_duplicate_windows).sample(rng);

        let max_offset = bytes.len() - window_size;
        let mut window_offsets: Vec<usize> = (0..num_windows)
            .map(|_| Uniform::new_inclusive(0, max_offset).sample(rng))
            .collect();

        window_offsets.sort_unstable();

        let first_window = window_offsets[0];

        let mut window_idx = 1;
        loop {
            let prev_window = window_offsets[window_idx - 1];
            let cur_window = window_offsets[window_idx];

            if cur_window < (prev_window + window_size) {
                window_offsets.remove(window_idx);
                window_idx -= 1;
            } else {
                for window_byte_idx in 0..window_size {
                    bytes[cur_window + window_byte_idx] = bytes[first_window + window_byte_idx];
                }
            }

            window_idx += 1;

            if window_idx >= window_offsets.len() {
                break;
            }
        }

        if window_offsets.len() < min_num_duplicate_windows {
            None
        } else {
            Some(window_offsets)
        }
    }

    fn roll_test_random_impl<H, S, W, R>(size: W, window: W)
    where
        H: Unsigned + std::fmt::Debug,
        S: Unsigned,
        W: NonZero<S>,
        R: RollingHashImpl<H, S, W>,
    {
        assert!(size.get() >= window.get());

        for i in 0..NUM_RANDOM_ITERATIONS {
            let mut rng = rand::rngs::SmallRng::seed_from_u64(i as _);

            let mut bytes = generate_random_bytes(&mut rng, size.get().to_usize());

            let duplicate_windows = generate_duplicate_windows(&mut rng, &mut bytes, window);

            let hash = RollingHash::<'_, H, S, W, R>::new(&bytes, window);

            let hash_len = bytes.len() - window.get().to_usize() + 1;
            assert_eq!(hash.len(), hash_len);

            let mut iter = hash.into_iter().enumerate();
            assert_eq!(iter.len(), hash_len);

            let mut duplicate_hash: Option<H> = None;

            while let Some((offset, hash)) = iter.next() {
                let window = &bytes[offset..offset + window.get().to_usize()];
                assert_eq!(
                    hash,
                    RollingHash::<'_, H, S, W, R>::hash_bytes(window).unwrap()
                );

                // `-1` to account for the returned item above.
                assert_eq!(iter.len(), hash_len - offset - 1);

                if let Some(duplicate_windows) = duplicate_windows.as_ref() {
                    if duplicate_windows.contains(&offset) {
                        if let Some(duplicate_hash) = duplicate_hash.as_ref() {
                            assert_eq!(hash, *duplicate_hash);
                        } else {
                            duplicate_hash.replace(hash);
                        }
                    }
                }
            }

            assert_eq!(iter.len(), 0);
            assert!(iter.next().is_none());
        }
    }

    #[test]
    fn slice_too_short_test() {
        let bytes = [0u8, 1, 2, 3, 4, 5, 6, 7];

        let window_16 = NonZeroU16::new(16).unwrap();
        let window_32 = NonZeroU32::new(16).unwrap();

        #[cfg(feature = "adler")]
        {
            slice_too_short_test_impl::<u16, u16, NonZeroU16, adler::HashAdler<_, _, _>>(
                &bytes, window_16,
            );
            slice_too_short_test_impl::<u32, u32, NonZeroU32, adler::HashAdler<_, _, _>>(
                &bytes, window_32,
            );
        }

        #[cfg(feature = "cyclic_poly")]
        {
            slice_too_short_test_impl::<u16, u16, NonZeroU16, cyclic_poly::HashCyclicPoly<_, _, _>>(
                &bytes, window_16,
            );
            slice_too_short_test_impl::<u32, u32, NonZeroU32, cyclic_poly::HashCyclicPoly<_, _, _>>(
                &bytes, window_32,
            );
        }
    }

    #[test]
    fn roll_test() {
        let bytes = [0u8, 1, 2, 3, 4, 5, 6, 7];

        let window_16 = NonZeroU16::new(4).unwrap();
        let window_32 = NonZeroU32::new(4).unwrap();

        #[cfg(feature = "adler")]
        {
            roll_test_impl::<u16, u16, NonZeroU16, adler::HashAdler<_, _, _>>(&bytes, window_16);
            roll_test_impl::<u32, u32, NonZeroU32, adler::HashAdler<_, _, _>>(&bytes, window_32);
        }

        #[cfg(feature = "cyclic_poly")]
        {
            roll_test_impl::<u16, u16, NonZeroU16, cyclic_poly::HashCyclicPoly<_, _, _>>(
                &bytes, window_16,
            );
            roll_test_impl::<u32, u32, NonZeroU32, cyclic_poly::HashCyclicPoly<_, _, _>>(
                &bytes, window_32,
            );
        }
    }

    #[test]
    fn roll_test_random() {
        let size_16 = NonZeroU16::new(u8::MAX as u16 + 1).unwrap();
        let window_16 = NonZeroU16::new(8).unwrap();

        let size_32 = NonZeroU32::new(u16::MAX as u32 + 1).unwrap();
        let window_32 = NonZeroU32::new(256).unwrap();

        #[cfg(feature = "adler")]
        {
            roll_test_random_impl::<u16, u16, NonZeroU16, adler::HashAdler<_, _, _>>(
                size_16, window_16,
            );
            roll_test_random_impl::<u32, u32, NonZeroU32, adler::HashAdler<_, _, _>>(
                size_32, window_32,
            );
        }

        #[cfg(feature = "cyclic_poly")]
        {
            roll_test_random_impl::<u16, u16, NonZeroU16, cyclic_poly::HashCyclicPoly<_, _, _>>(
                size_16, window_16,
            );
            roll_test_random_impl::<u32, u32, NonZeroU32, cyclic_poly::HashCyclicPoly<_, _, _>>(
                size_32, window_32,
            );
        }
    }
}
