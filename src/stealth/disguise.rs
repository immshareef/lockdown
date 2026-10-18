use rand::Rng;

const BENIGN_EXTENSIONS: &[&str] = &[
    ".dat", ".tmp", ".cache", ".bin", ".sys", ".log", ".bak", ".old", ".swp", ".dmp",
];

const PREFIXES: &[&str] = &[
    "sys", "cache", "temp", "backup", "core", "data", "index", "store", "blob", "chunk",
];

const TAGS: &[&str] = &[
    "32", "64", "128", "256", "512", "1024", "a1", "b2", "c3", "x7", "f0", "e9",
];

/// Random benign-looking name like `cache_a1_9034.tmp`.
pub fn generate_disguised_name() -> String {
    let mut rng = rand::thread_rng();
    let prefix = PREFIXES[rng.gen_range(0..PREFIXES.len())];
    let tag = TAGS[rng.gen_range(0..TAGS.len())];
    let ext = BENIGN_EXTENSIONS[rng.gen_range(0..BENIGN_EXTENSIONS.len())];
    let random_suffix: u32 = rng.gen_range(1000..=9999);
    format!("{}_{}_{}{}", prefix, tag, random_suffix, ext)
}
