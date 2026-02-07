use wreq_util::Emulation;

/// Browser identity preset for TLS fingerprinting and header generation.
#[derive(Clone)]
pub struct Preset {
    pub name: &'static str,
    pub user_agent: &'static str,
    pub emulation: Emulation,
}

pub fn get_preset(name: &str) -> Preset {
    match name {
        "chrome-143" => Preset {
            name: "chrome-143",
            user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36",
            emulation: Emulation::Chrome143,
        },
        "firefox-133" => Preset {
            name: "firefox-133",
            user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0",
            emulation: Emulation::Firefox133,
        },
        "safari-18" => Preset {
            name: "safari-18",
            user_agent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15",
            emulation: Emulation::Safari18,
        },
        _ => get_preset("chrome-143"),
    }
}
