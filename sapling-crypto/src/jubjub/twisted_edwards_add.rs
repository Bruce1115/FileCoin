#[link(name = "sncrypto-twisted", kind = "static")]
extern "C" {
    fn ext_twisted_ed_add_4w(a: &[u64; 16], b: &[u64; 16], res: &mut [u64; 16]);
    fn ext_twisted_ed_precomp_4w(a: &[u64; 16], res: &mut [u64; 16]);
}

#[inline]
pub fn ext_twisted_ed_add_256(a: &[u64; 16], b: &[u64; 16], res: &mut [u64; 16]) {
    unsafe { ext_twisted_ed_add_4w(a, b, res) }
}

#[inline]
pub fn ext_twisted_ed_precomp_256(a: &[u64; 16], res: &mut [u64; 16]) {
    unsafe { ext_twisted_ed_precomp_4w(a, res) }
}
