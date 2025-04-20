pub trait IntTraits: Copy + core::ops::BitAnd<Output = Self> + core::ops::BitOr<Output = Self> + core::ops::Not<Output = Self> + super::disjoint_bitor::DisjointBitOr {
    fn sign_bit(self) -> bool;
    #[inline(always)]
    fn merge_bits(self, b: Self, mask: Self) -> Self {
        super::merge_bits(self, b, mask)
    }
}