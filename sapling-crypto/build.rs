#[cfg(target_arch = "x86_64")]
extern crate cc;

fn main() {
    if cfg!(target_arch = "x86_64") {
        cc::Build::new()
            .flag("-c")
            .file("./asm/ext_twisted_ed_add.S")
            .compile("libsncrypto-twisted.a");
    }
}
