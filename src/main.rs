mod browser;
mod detect;
mod output;
mod timezone;

use clap::Parser;
use detect::{run, Options};
use futures_util::stream::{self, StreamExt};
use std::time::Instant;

#[derive(Parser)]
#[command(name = "proxy-detector")]
#[command(about = "Detect proxy/VPN usage via TLS fingerprinting")]
struct Cli {
    /// Proxy URL to test (http://, socks5://)
    #[arg(long, default_value = "", conflicts_with = "file")]
    proxy: String,

    /// File with one proxy per line (blank lines and #comments skipped)
    #[arg(long)]
    file: Option<String>,

    /// Max concurrent tests (only with --file)
    #[arg(long, default_value = "200")]
    concurrency: usize,

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

fn parse_proxy_file(path: &str) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let content = std::fs::read_to_string(path)?;
    let proxies: Vec<String> = content
        .lines()
        .map(|line| line.trim())
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(|line| normalize_proxy(line))
        .collect();

    if proxies.is_empty() {
        return Err(format!("no proxies found in {}", path).into());
    }
    Ok(proxies)
}

async fn run_bulk(
    proxies: Vec<String>,
    browser: &str,
    timezone: &Option<String>,
    verbose: bool,
    json_output: bool,
    concurrency: usize,
) {
    let total = proxies.len();
    if !json_output {
        eprintln!("Bulk scan: {} proxies, concurrency {}", total, concurrency);
        eprintln!();
    }

    let mut results = stream::iter(proxies.into_iter().map(|proxy_url| {
        let browser = browser.to_string();
        let timezone = timezone.clone();
        async move {
            let start = Instant::now();
            let opts = Options {
                proxy_url: Some(proxy_url.clone()),
                browser_name: browser,
                timezone_iana: timezone,
                verbose: false,
                json_output: false,
            };
            let log = |_msg: &str| {};
            let result = run(&opts, log).await;
            let elapsed = start.elapsed().as_secs_f64();
            (proxy_url, result, elapsed)
        }
    }))
    .buffer_unordered(concurrency);

    let mut clean_count: usize = 0;
    let mut detected_count: usize = 0;
    let mut error_count: usize = 0;

    while let Some((proxy_url, result, elapsed)) = results.next().await {
        let display = mask_proxy(&proxy_url);
        match result {
            Ok(ref res) => {
                let status = output::classify_result(res);
                if json_output {
                    output::render_bulk_json_line(&proxy_url, res);
                } else {
                    output::render_bulk_line(&display, res, elapsed, &status);
                    if verbose {
                        output::render_table(res, &res.exit_ip, true);
                    }
                }
                match status {
                    output::BulkStatus::Clean => clean_count += 1,
                    output::BulkStatus::Detected => detected_count += 1,
                }
            }
            Err(ref err) => {
                error_count += 1;
                if json_output {
                    output::render_bulk_json_error(&proxy_url, &err.to_string());
                } else {
                    output::render_bulk_error(&display, &err.to_string(), elapsed);
                }
            }
        }
    }

    output::render_bulk_summary(total, clean_count, detected_count, error_count);
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    // Bulk mode: --file takes precedence
    if let Some(ref path) = cli.file {
        let proxies = match parse_proxy_file(path) {
            Ok(list) => list,
            Err(err) => {
                eprintln!("Error reading proxy file: {}", err);
                std::process::exit(1);
            }
        };

        let timezone = if cli.timezone.is_empty() {
            None
        } else {
            Some(cli.timezone.clone())
        };

        run_bulk(
            proxies,
            &cli.browser,
            &timezone,
            cli.verbose,
            cli.json,
            cli.concurrency,
        )
        .await;
        return;
    }

    // Single-proxy mode (existing behavior)
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
        Err(err) => {
            eprintln!("Error: {}", err);
            std::process::exit(1);
        }
    }
}
