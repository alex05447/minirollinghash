use {crate::*, miniunchecked::*, miniunsigned::*};

pub struct HashRsync<H, W> {
    a: H,
    b: H,
    window_truncated: H,
    #[cfg(debug_assertions)]
    window: W,
    #[cfg(not(debug_assertions))]
    _marker: std::marker::PhantomData<W>,
}

fn truncate<H, W>(window: W) -> H
where
    H: Unsigned,
    W: Unsigned,
{
    unsafe {
        H::from_usize(window.to_usize() & H::max_value().to_usize())
            .unwrap_unchecked_dbg_msg("`window` truncation to `H::BITS` must succeed")
    }
}

impl<H, W> HashRsync<H, W>
where
    H: Unsigned,
    W: NonZero,
{
    fn new(window: W) -> Self {
        let window_truncated = truncate(window.get());

        Self {
            a: H::zero(),
            b: H::zero(),
            window_truncated,
            #[cfg(debug_assertions)]
            window,
            #[cfg(not(debug_assertions))]
            _marker: Default::default(),
        }
    }

    fn hash_bytes(&mut self, bytes: &[u8]) {
        #[cfg(debug_assertions)]
        {
            debug_assert_eq!(bytes.len(), self.window.get().to_usize());
        }

        for (idx, byte) in bytes.iter().cloned().map(Self::byte).enumerate() {
            let idx = truncate(self.window_truncated.to_usize().wrapping_sub(idx));

            self.a = self.a.wrapping_add(&byte) & Self::mask();
            self.b = self.b.wrapping_add(&byte.wrapping_mul(&idx)) & Self::mask();
        }
    }

    fn roll_hash(&mut self, old_byte: u8, new_byte: u8) {
        let old_byte = Self::byte(old_byte);
        let new_byte = Self::byte(new_byte);

        self.a = (self.a.wrapping_add(&new_byte).wrapping_sub(&old_byte)) & Self::mask();
        self.b = (self
            .b
            .wrapping_add(&self.a)
            .wrapping_sub(&old_byte.wrapping_mul(&self.window_truncated)))
            & Self::mask();
    }

    fn hash(&self) -> H {
        let b_offset = (H::BITS / 2) as _;
        (self.b << b_offset) | self.a
    }

    fn byte(byte: u8) -> H {
        <H as Unsigned>::from_u8(byte)
    }

    fn mask() -> H {
        H::max_value() >> (H::BITS / 2) as _
    }
}

impl<H, W> RollingHashImpl<H, W> for HashRsync<H, W>
where
    H: Unsigned,
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
