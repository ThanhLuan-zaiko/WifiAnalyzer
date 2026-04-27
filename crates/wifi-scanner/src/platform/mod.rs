use crate::WifiScanner;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(windows)]
mod windows;

pub fn default_scanner() -> Box<dyn WifiScanner + Send + Sync> {
    #[cfg(windows)]
    {
        Box::<windows::WindowsWlanScanner>::default()
    }

    #[cfg(target_os = "linux")]
    {
        Box::<linux::LinuxNmcliScanner>::default()
    }

    #[cfg(target_os = "macos")]
    {
        Box::<macos::MacosAirportScanner>::default()
    }

    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    {
        Box::<crate::MockScanner>::default()
    }
}
