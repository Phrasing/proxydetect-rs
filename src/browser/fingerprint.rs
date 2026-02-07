use std::fmt::Write;

/// Browser navigator properties for fingerprint generation.
struct BrowserProperties {
    boolean_fingerprint: u32,
    hardware_concurrency: i32,
    device_memory: Option<&'static str>,
    platform: &'static str,
    oscpu: Option<&'static str>,
    cpu_class: Option<&'static str>,
    vendor: &'static str,
    build_id: Option<&'static str>,
    product: &'static str,
    product_sub: &'static str,
    plugins_support: bool,
    max_touch_points: i32,
    language: &'static str,
    languages: &'static str,
    session_storage: bool,
    local_storage: bool,
    indexed_db: bool,
    open_database: bool,
    cookie_enabled: bool,
    do_not_track: &'static str,
    sayswho: &'static str,
    load_purpose: &'static str,
    webdriver: bool,
    dimensions: &'static str,
    geolocation: bool,
    vibrate: bool,
    get_battery: bool,
    webrtc_key: bool,
    phantom: bool,
    window_webdriver: bool,
    dom_automation: bool,
    auto: bool,
    wd1: bool,
    xpath_result: bool,
    wd2: bool,
    selenium: bool,
}

fn build_fingerprint_string(props: &BrowserProperties) -> String {
    let mut s = String::with_capacity(1024);

    write!(s, "booleanFingerprint:{};", props.boolean_fingerprint).unwrap();
    write!(s, "hardwareConcurrency:{};", props.hardware_concurrency).unwrap();
    write!(s, "deviceMemory:{};", props.device_memory.unwrap_or("")).unwrap();
    write!(s, "platform:{};", props.platform).unwrap();
    write!(s, "oscpu:{};", props.oscpu.unwrap_or("")).unwrap();
    write!(s, "cpuClass:{};", props.cpu_class.unwrap_or("")).unwrap();
    write!(s, "vendor:{};", props.vendor).unwrap();
    write!(s, "buildID:{};", props.build_id.unwrap_or("")).unwrap();
    write!(s, "product:{};", props.product).unwrap();
    write!(s, "productSub:{};", props.product_sub).unwrap();
    write!(s, "pluginsSupport:{};", props.plugins_support).unwrap();
    write!(s, "maxTouchPoints:{};", props.max_touch_points).unwrap();
    write!(s, "language:{};", props.language).unwrap();
    write!(s, "languages:{};", props.languages).unwrap();
    write!(s, "sessionStorage:{};", props.session_storage).unwrap();
    write!(s, "localStorage:{};", props.local_storage).unwrap();
    write!(s, "indexedDB:{};", props.indexed_db).unwrap();
    write!(s, "openDatabase:{};", props.open_database).unwrap();
    write!(s, "navigatorCookieEnabled:{};", props.cookie_enabled).unwrap();
    write!(s, "doNotTrack:{};", props.do_not_track).unwrap();
    write!(s, "sayswho:{};", props.sayswho).unwrap();
    write!(s, "loadPurpose:{};", props.load_purpose).unwrap();
    write!(s, "webdriver:{};", props.webdriver).unwrap();
    write!(s, "dimensions:{};", props.dimensions).unwrap();
    write!(s, "geolocation:{};", props.geolocation).unwrap();
    write!(s, "vibrate:{};", props.vibrate).unwrap();
    write!(s, "getBattery:{};", props.get_battery).unwrap();
    write!(s, "webrtcKey:{};", props.webrtc_key).unwrap();
    write!(s, "_phantom:{};", props.phantom).unwrap();
    write!(s, "webdriver:{};", props.window_webdriver).unwrap();
    write!(s, "domAutomation:{};", props.dom_automation).unwrap();
    write!(s, "auto:{};", props.auto).unwrap();
    write!(s, "wd1:{};", props.wd1).unwrap();
    write!(s, "XPathResult:{};", props.xpath_result).unwrap();
    write!(s, "wd2:{};", props.wd2).unwrap();
    write!(s, "selenium:{};", props.selenium).unwrap();

    s
}

fn chrome_properties() -> BrowserProperties {
    BrowserProperties {
        boolean_fingerprint: 25952189,
        hardware_concurrency: 16,
        device_memory: Some("8"),
        platform: "Win32",
        oscpu: None,
        cpu_class: None,
        vendor: "Google Inc.",
        build_id: None,
        product: "Gecko",
        product_sub: "20030107",
        plugins_support: true,
        max_touch_points: 0,
        language: "en-US",
        languages: "en-US,en",
        session_storage: true,
        local_storage: true,
        indexed_db: true,
        open_database: false,
        cookie_enabled: true,
        do_not_track: "",
        sayswho: "",
        load_purpose: "",
        webdriver: false,
        dimensions: "1920,1080",
        geolocation: true,
        vibrate: true,
        get_battery: true,
        webrtc_key: true,
        phantom: false,
        window_webdriver: false,
        dom_automation: false,
        auto: false,
        wd1: false,
        xpath_result: true,
        wd2: false,
        selenium: false,
    }
}

fn firefox_properties() -> BrowserProperties {
    BrowserProperties {
        boolean_fingerprint: 26066385,
        hardware_concurrency: 16,
        device_memory: None,
        platform: "Win32",
        oscpu: Some("Windows NT 10.0; Win64; x64"),
        cpu_class: None,
        vendor: "",
        build_id: Some("20181001000000"),
        product: "Gecko",
        product_sub: "20100101",
        plugins_support: true,
        max_touch_points: 0,
        language: "en-US",
        languages: "en-US,en",
        session_storage: true,
        local_storage: true,
        indexed_db: true,
        open_database: false,
        cookie_enabled: true,
        do_not_track: "unspecified",
        sayswho: "",
        load_purpose: "",
        webdriver: false,
        dimensions: "1920,1080",
        geolocation: true,
        vibrate: true,
        get_battery: true,
        webrtc_key: true,
        phantom: false,
        window_webdriver: false,
        dom_automation: false,
        auto: false,
        wd1: false,
        xpath_result: true,
        wd2: false,
        selenium: false,
    }
}

fn safari_properties() -> BrowserProperties {
    BrowserProperties {
        boolean_fingerprint: 25969049,
        hardware_concurrency: 8,
        device_memory: None,
        platform: "MacIntel",
        oscpu: None,
        cpu_class: None,
        vendor: "Apple Computer, Inc.",
        build_id: None,
        product: "Gecko",
        product_sub: "20030107",
        plugins_support: true,
        max_touch_points: 0,
        language: "en-US",
        languages: "en-US,en",
        session_storage: true,
        local_storage: true,
        indexed_db: true,
        open_database: true,
        cookie_enabled: true,
        do_not_track: "",
        sayswho: "",
        load_purpose: "",
        webdriver: false,
        dimensions: "1920,1080",
        geolocation: true,
        vibrate: false,
        get_battery: false,
        webrtc_key: true,
        phantom: false,
        window_webdriver: false,
        dom_automation: false,
        auto: false,
        wd1: false,
        xpath_result: true,
        wd2: false,
        selenium: false,
    }
}

/// MurmurHash3 x86 32-bit (v3) implementation.
fn murmur_hash3_v3(data: &[u8], seed: u32) -> u32 {
    let length = data.len();
    let nblocks = length / 4;
    let mut hash = seed;

    const C1: u32 = 0xcc9e2d51;
    const C2: u32 = 0x1b873593;

    // Body - process 4-byte blocks
    for i in 0..nblocks {
        let idx = i * 4;
        let mut block = u32::from(data[idx])
            | (u32::from(data[idx + 1]) << 8)
            | (u32::from(data[idx + 2]) << 16)
            | (u32::from(data[idx + 3]) << 24);

        block = imul32(block, C1);
        block = (block << 15) | (block >> 17);
        block = imul32(block, C2);

        hash ^= block;
        hash = (hash << 13) | (hash >> 19);
        hash = imul32(hash, 5).wrapping_add(0xe6546b64);
    }

    // Tail
    let tail = &data[nblocks * 4..];
    let mut tail_block: u32 = 0;
    match tail.len() {
        3 => {
            tail_block ^= u32::from(tail[2]) << 16;
            tail_block ^= u32::from(tail[1]) << 8;
            tail_block ^= u32::from(tail[0]);
            tail_block = imul32(tail_block, C1);
            tail_block = (tail_block << 15) | (tail_block >> 17);
            tail_block = imul32(tail_block, C2);
            hash ^= tail_block;
        }
        2 => {
            tail_block ^= u32::from(tail[1]) << 8;
            tail_block ^= u32::from(tail[0]);
            tail_block = imul32(tail_block, C1);
            tail_block = (tail_block << 15) | (tail_block >> 17);
            tail_block = imul32(tail_block, C2);
            hash ^= tail_block;
        }
        1 => {
            tail_block ^= u32::from(tail[0]);
            tail_block = imul32(tail_block, C1);
            tail_block = (tail_block << 15) | (tail_block >> 17);
            tail_block = imul32(tail_block, C2);
            hash ^= tail_block;
        }
        _ => {}
    }

    // Finalization
    hash ^= length as u32;
    hash ^= hash >> 16;
    hash = imul32(hash, 0x85ebca6b);
    hash ^= hash >> 13;
    hash = imul32(hash, 0xc2b2ae35);
    hash ^= hash >> 16;

    hash
}

/// JavaScript-style 32-bit integer multiplication (Math.imul equivalent).
fn imul32(val: u32, mul: u32) -> u32 {
    ((val & 0xffff).wrapping_mul(mul)).wrapping_add(((val >> 16).wrapping_mul(mul) & 0xffff) << 16)
}

/// Compute the MurmurHash3 fingerprint for a browser preset.
pub fn compute_fingerprint(preset_name: &str) -> u32 {
    let props = match preset_name {
        "firefox-133" => firefox_properties(),
        "safari-18" => safari_properties(),
        _ => chrome_properties(),
    };
    let input = build_fingerprint_string(&props);
    murmur_hash3_v3(input.as_bytes(), 0)
}
