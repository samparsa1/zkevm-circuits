/// Version
pub mod version {
    /// Major version
    pub const MAJOR: u32 = 0;
    /// Minor version
    pub const MINOR: u32 = 1;
    /// Patch version
    pub const PATCH: u32 = 0;

    /// Export versions as string
    pub fn as_string() -> String {
        format!("{}.{}.{}", MAJOR, MINOR, PATCH)
    }
}

mod tests {
    use crate::version::version;

    #[test]
    fn test_version_string() {
        let expected = "0.1.0";

        assert_eq!(version::MAJOR, 0, "wrong version");
        assert_eq!(version::MINOR, 1, "wrong version");
        assert_eq!(version::PATCH, 0, "wrong version");
        assert_eq!(version::as_string(), expected, "wrong version");
    }
}
