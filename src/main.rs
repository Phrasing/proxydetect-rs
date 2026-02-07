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

    let opts = Options {
        proxy_url: if cli.proxy.is_empty() {
            None
        } else {
            Some(cli.proxy.clone())
        },
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
