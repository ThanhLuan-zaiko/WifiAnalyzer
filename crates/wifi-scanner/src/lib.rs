mod mock;
mod platform;

use anyhow::Result;
use wifi_core::ScanRecord;

pub use mock::MockScanner;

pub trait WifiScanner {
    fn name(&self) -> &'static str;
    fn scan(&self) -> Result<Vec<ScanRecord>>;
}

pub fn default_scanner() -> Box<dyn WifiScanner + Send + Sync> {
    platform::default_scanner()
}
