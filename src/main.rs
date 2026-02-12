mod browser;
mod detect;
mod ipapi;
mod output;
mod timezone;

use clap::Parser;
use detect::{run, Options};
use futures_util::stream::{self, StreamExt};
use std::io::Write;
use std::time::{Duration, Instant};

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

    /// Enrich results with ipapi.is intelligence (queried through the proxy).
    #[arg(long)]
    ipapi: bool,

    /// Filter out proxies with abuser score above this threshold (implies --ipapi).
    #[arg(long)]
    max_fraud_score: Option<f64>,

    /// Only output fully clean proxies: detection clean + abuser_score <= 0.0001.
    #[arg(long)]
    clean: bool,

    /// Write results to CSV file (default: results.csv)
    #[arg(long, default_missing_value = "results.csv", num_args = 0..=1)]
    csv: Option<String>,
}

const CLEAN_ABUSER_THRESHOLD: f64 = 0.0001;

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
        .map(normalize_proxy)
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
    csv_path: Option<&str>,
    ipapi_enabled: bool,
    max_fraud_score: Option<f64>,
    clean_only: bool,
) {
    let total = proxies.len();
    let concurrency = concurrency.max(1);
    let preset = browser::get_preset(browser);

    if !json_output {
        eprintln!("Bulk scan: {} proxies, concurrency {}", total, concurrency);
        eprintln!();
    }

    let mut csv_file = csv_path.map(|path| {
        let mut file = std::fs::File::create(path).expect("failed to create CSV file");
        writeln!(file, "{}", output::csv_header(ipapi_enabled)).unwrap();
        file
    });

    let mut results = stream::iter(proxies.into_iter().enumerate().map(|(idx, proxy_url)| {
        let browser = browser.to_string();
        let timezone = timezone.clone();
        let preset = preset.clone();
        async move {
            // Stagger launches: spread concurrent tasks over time to avoid
            // overwhelming the detection server with simultaneous telemetry POSTs.
            // Each batch of `concurrency` tasks is spread over ~20s (100ms apart).
            let stagger_ms = (idx % concurrency) as u64 * 100;
            tokio::time::sleep(Duration::from_millis(stagger_ms)).await;

            if !json_output {
                let display = mask_proxy(&proxy_url);
                output::render_bulk_start_line(&display, idx + 1, total);
            }

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
            let (ip_info, ipapi_error) = if ipapi_enabled {
                match ipapi::lookup(Some(proxy_url.as_str()), &preset).await {
                    Ok(info) => (Some(info), None),
                    Err(first_err) => {
                        tokio::time::sleep(Duration::from_millis(250)).await;
                        match ipapi::lookup(Some(proxy_url.as_str()), &preset).await {
                            Ok(info) => (Some(info), None),
                            Err(second_err) => {
                                (None, Some(format!("{} | retry: {}", first_err, second_err)))
                            }
                        }
                    }
                }
            } else {
                (None, None)
            };
            let elapsed = start.elapsed().as_secs_f64();
            (idx, proxy_url, result, ip_info, ipapi_error, elapsed)
        }
    }))
    .buffer_unordered(concurrency);

    let mut clean_count: usize = 0;
    let mut detected_count: usize = 0;
    let mut filtered_count: usize = 0;
    let mut error_count: usize = 0;
    let mut ipapi_abuser_score_sum: f64 = 0.0;
    let mut ipapi_abuser_score_count: usize = 0;
    let mut completed_count: usize = 0;

    while let Some((_idx, proxy_url, result, ip_info, ipapi_error, elapsed)) = results.next().await
    {
        completed_count += 1;
        let progress = format!("[{}/{}]", completed_count, total);
        let display = mask_proxy(&proxy_url);
        if verbose {
            if let Some(ref err) = ipapi_error {
                eprintln!("ipapi lookup failed for {}: {}", display, err);
            }
        }
        if let Some(ref info) = ip_info {
            ipapi_abuser_score_sum += info.abuser_score;
            ipapi_abuser_score_count += 1;
        }

        if clean_only {
            let main_clean = result
                .as_ref()
                .map(|res| matches!(output::classify_result(res), output::BulkStatus::Clean))
                .unwrap_or(false);
            let ipapi_clean = ip_info
                .as_ref()
                .map(|info| info.abuser_score <= CLEAN_ABUSER_THRESHOLD)
                .unwrap_or(false);
            if !(main_clean && ipapi_clean) {
                filtered_count += 1;
                continue;
            }
        }

        let is_filtered = max_fraud_score
            .and_then(|threshold| ip_info.as_ref().map(|info| info.abuser_score > threshold))
            .unwrap_or(false);

        if is_filtered {
            filtered_count += 1;
            if json_output {
                match result {
                    Ok(ref res) => output::render_bulk_json_line(
                        &proxy_url,
                        res,
                        ip_info.as_ref(),
                        true,
                        max_fraud_score,
                    ),
                    Err(ref err) => output::render_bulk_json_error(
                        &proxy_url,
                        &err.to_string(),
                        ip_info.as_ref(),
                        true,
                        max_fraud_score,
                    ),
                }
            } else {
                let threshold = max_fraud_score.unwrap_or_default();
                let score = ip_info
                    .as_ref()
                    .map(|info| info.abuser_score)
                    .unwrap_or(0.0);
                let exit_ip = match &result {
                    Ok(res) => res.exit_ip.as_str(),
                    Err(_) => ip_info
                        .as_ref()
                        .and_then(|info| {
                            if info.ip.is_empty() {
                                None
                            } else {
                                Some(info.ip.as_str())
                            }
                        })
                        .unwrap_or("unknown"),
                };

                output::render_bulk_filtered_line(
                    &progress, &display, exit_ip, score, threshold, elapsed,
                );
            }

            if let (Some(ref mut file), Ok(ref res)) = (&mut csv_file, &result) {
                let _ = writeln!(
                    file,
                    "{}",
                    output::csv_row(&proxy_url, res, ip_info.as_ref(), ipapi_enabled)
                );
            } else if let (Some(ref mut file), Err(ref err)) = (&mut csv_file, &result) {
                let _ = writeln!(
                    file,
                    "{}",
                    output::csv_error_row(&proxy_url, &err.to_string(), ipapi_enabled)
                );
            }

            continue;
        }

        match result {
            Ok(ref res) => {
                let status = output::classify_result(res);
                if json_output {
                    output::render_bulk_json_line(
                        &proxy_url,
                        res,
                        ip_info.as_ref(),
                        false,
                        max_fraud_score,
                    );
                } else {
                    output::render_bulk_line(
                        &progress,
                        &display,
                        res,
                        elapsed,
                        &status,
                        ip_info.as_ref(),
                    );
                    if verbose {
                        output::render_table(res, &res.exit_ip, true);
                        if let Some(ref info) = ip_info {
                            output::render_ip_intelligence(info);
                        }
                    }
                }
                if let Some(ref mut file) = csv_file {
                    let _ = writeln!(
                        file,
                        "{}",
                        output::csv_row(&proxy_url, res, ip_info.as_ref(), ipapi_enabled)
                    );
                }
                match status {
                    output::BulkStatus::Clean => clean_count += 1,
                    output::BulkStatus::Detected => detected_count += 1,
                }
            }
            Err(ref err) => {
                error_count += 1;
                if json_output {
                    output::render_bulk_json_error(
                        &proxy_url,
                        &err.to_string(),
                        ip_info.as_ref(),
                        false,
                        max_fraud_score,
                    );
                } else {
                    output::render_bulk_error(
                        &progress,
                        &display,
                        &err.to_string(),
                        elapsed,
                        ip_info.as_ref(),
                    );
                }
                if let Some(ref mut file) = csv_file {
                    let _ = writeln!(
                        file,
                        "{}",
                        output::csv_error_row(&proxy_url, &err.to_string(), ipapi_enabled)
                    );
                }
            }
        }
    }

    output::render_bulk_summary(
        total,
        clean_count,
        detected_count,
        filtered_count,
        error_count,
        if ipapi_abuser_score_count > 0 {
            Some(ipapi_abuser_score_sum / ipapi_abuser_score_count as f64)
        } else {
            None
        },
        ipapi_abuser_score_count,
    );

    if let Some(path) = csv_path {
        eprintln!("Results written to {}", path);
    }
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let ipapi_enabled = cli.ipapi || cli.max_fraud_score.is_some() || cli.clean;

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
            cli.csv.as_deref(),
            ipapi_enabled,
            cli.max_fraud_score,
            cli.clean,
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

    let single_start = Instant::now();
    let single_preset = browser::get_preset(&cli.browser);
    let detection_result = run(&opts, log).await;
    let (ip_info, ipapi_error) = if ipapi_enabled {
        match ipapi::lookup(opts.proxy_url.as_deref(), &single_preset).await {
            Ok(info) => (Some(info), None),
            Err(first_err) => {
                tokio::time::sleep(Duration::from_millis(250)).await;
                match ipapi::lookup(opts.proxy_url.as_deref(), &single_preset).await {
                    Ok(info) => (Some(info), None),
                    Err(second_err) => {
                        (None, Some(format!("{} | retry: {}", first_err, second_err)))
                    }
                }
            }
        }
    } else {
        (None, None)
    };
    let single_elapsed = single_start.elapsed().as_secs_f64();

    if opts.verbose {
        if let Some(ref err) = ipapi_error {
            eprintln!("ipapi lookup failed: {}", err);
        }
    }

    match detection_result {
        Ok(result) => {
            let main_clean = matches!(output::classify_result(&result), output::BulkStatus::Clean);
            let ipapi_clean = ip_info
                .as_ref()
                .map(|info| info.abuser_score <= CLEAN_ABUSER_THRESHOLD)
                .unwrap_or(false);
            let passes_clean_only = main_clean && ipapi_clean;

            if cli.clean && !passes_clean_only {
                if opts.verbose {
                    let score = ip_info
                        .as_ref()
                        .map(|info| format!("{:.4}", info.abuser_score))
                        .unwrap_or_else(|| "n/a".to_string());
                    eprintln!(
                        "Suppressed by --clean (main_clean={}, abuser_score={}, threshold={:.4})",
                        main_clean, score, CLEAN_ABUSER_THRESHOLD
                    );
                }
                if let Some(ref csv_path) = cli.csv {
                    let mut file =
                        std::fs::File::create(csv_path).expect("failed to create CSV file");
                    writeln!(file, "{}", output::csv_header(ipapi_enabled)).unwrap();
                    eprintln!("Results written to {}", csv_path);
                }
                return;
            }

            let is_filtered = cli
                .max_fraud_score
                .and_then(|threshold| ip_info.as_ref().map(|info| info.abuser_score > threshold))
                .unwrap_or(false);

            if opts.json_output {
                if !ipapi_enabled {
                    output::render_json(&result);
                } else {
                    output::render_bulk_json_line(
                        proxy_url.as_deref().unwrap_or("direct"),
                        &result,
                        ip_info.as_ref(),
                        is_filtered,
                        cli.max_fraud_score,
                    );
                }
            } else if is_filtered {
                let display = proxy_url
                    .as_deref()
                    .map(mask_proxy)
                    .unwrap_or_else(|| "direct".to_string());
                output::render_bulk_filtered_line(
                    "[1/1]",
                    &display,
                    &result.exit_ip,
                    ip_info
                        .as_ref()
                        .map(|info| info.abuser_score)
                        .unwrap_or(0.0),
                    cli.max_fraud_score.unwrap_or_default(),
                    single_elapsed,
                );
            } else {
                output::render_table(&result, &result.exit_ip, opts.verbose);
                if let Some(ref info) = ip_info {
                    output::render_ip_intelligence(info);
                }
            }

            if let Some(ref csv_path) = cli.csv {
                let csv_proxy = proxy_url.clone().unwrap_or_else(|| "direct".to_string());
                let mut file = std::fs::File::create(csv_path).expect("failed to create CSV file");
                writeln!(file, "{}", output::csv_header(ipapi_enabled)).unwrap();
                writeln!(
                    file,
                    "{}",
                    output::csv_row(&csv_proxy, &result, ip_info.as_ref(), ipapi_enabled)
                )
                .unwrap();
                eprintln!("Results written to {}", csv_path);
            }
        }
        Err(err) => {
            eprintln!("Error: {}", err);
            std::process::exit(1);
        }
    }
}
