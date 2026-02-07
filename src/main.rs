mod browser;
mod detect;
mod output;
mod timezone;

use clap::Parser;
use detect::{run, Options};

#[derive(Parser)]
#[command(name = "proxy-detector")]
#[command(about = "Detect proxy/VPN usage via TLS fingerprinting")]
struct Cli {
    /// Proxy URL to test (http://, socks5://)
    #[arg(long, default_value = "")]
    proxy: String,

    /// Browser preset: chrome-143, firefox-133, safari-18
    #[arg(long, default_value = "chrome-143")]
    browser: String,

    /// Override IANA timezone (default: auto from exit IP)
    #[arg(long, default_value = "")]
    timezone: String,

    /// Show detailed test info
    #[arg(long)]
    verbose: bool,

    /// Output raw JSON
    #[arg(long)]
    json: bool,
}

fn normalize_proxy(proxy_str: &str) -> String {
    // If it already looks like a URL with user info (contains @), trust it.
    if proxy_str.contains('@') {
        if !proxy_str.contains("://") {
            return format!("http://{}", proxy_str);
        }
        return proxy_str.to_string();
    }

    let (scheme, rest) = if let Some(idx) = proxy_str.find("://") {
        (&proxy_str[..idx], &proxy_str[idx + 3..])
    } else {
        ("http", proxy_str)
    };

    let parts: Vec<&str> = rest.split(':').collect();
    if parts.len() >= 4 {
        // Simple heuristic: 2nd part must be a port number (host:port:user:pass)
        if parts[1].parse::<u16>().is_ok() {
            let host = parts[0];
            let port = parts[1];
            let user = parts[2];
            let pass = parts[3..].join(":");
            return format!("{}://{}:{}@{}:{}", scheme, user, pass, host, port);
        }
    }

    if !proxy_str.contains("://") {
        return format!("{}://{}", scheme, proxy_str);
    }

    proxy_str.to_string()
}

fn mask_proxy(proxy_url: &str) -> String {
    if let Some(idx) = proxy_url.find('@') {
        let scheme_end = proxy_url.find("://").map(|i| i + 3).unwrap_or(0);
        let host = &proxy_url[idx + 1..];
        format!("{}***@{}", &proxy_url[..scheme_end], host)
    } else {
        proxy_url.to_string()
    }
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    let proxy_url = if cli.proxy.is_empty() {
        None
    } else {
        Some(normalize_proxy(&cli.proxy))
    };

    let opts = Options {
        proxy_url: proxy_url.clone(),
        browser_name: cli.browser.clone(),
        timezone_iana: if cli.timezone.is_empty() {
            None
        } else {
            Some(cli.timezone.clone())
        },
        verbose: cli.verbose,
        json_output: cli.json,
    };

    let log = |msg: &str| {
        if opts.verbose {
            eprintln!("{}", msg);
        }
    };

    if !opts.json_output {
        if let Some(ref proxy) = opts.proxy_url {
            eprintln!("Scanning via {}...", mask_proxy(proxy));
        } else {
            eprintln!("Scanning direct connection...");
        }
    }

    match run(&opts, log).await {
        Ok(result) => {
            if opts.json_output {
                output::render_json(&result);
            } else {
                output::render_table(&result, &result.exit_ip, opts.verbose);
            }
        }
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    }
}
