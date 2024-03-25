use littlefs2::object_safe::DynFilesystem;

#[derive(Debug)]
pub struct Migrator {
    /// The function performing the migration
    ///
    /// First argument is the Internal Filesystem, second argument is the External
    pub migrate: fn(&dyn DynFilesystem, &dyn DynFilesystem) -> Result<(), littlefs2::io::Error>,

    /// The version of the storage for which the migration needs to be run
    pub version: u32,
}
