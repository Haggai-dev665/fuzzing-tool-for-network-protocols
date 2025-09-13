use log::{info, warn, error};
use std::io::Write;

pub fn setup_logging(verbose: bool) {
    let log_level = if verbose {
        log::LevelFilter::Debug
    } else {
        log::LevelFilter::Info
    };
    
    env_logger::Builder::from_default_env()
        .filter_level(log_level)
        .format(|buf, record| {
            writeln!(
                buf,
                "[{}] [{}] [{}:{}] {}",
                chrono::Utc::now().format("%Y-%m-%d %H:%M:%S%.3f"),
                record.level(),
                record.file().unwrap_or("unknown"),
                record.line().unwrap_or(0),
                record.args()
            )
        })
        .init();
}

pub fn log_fuzzing_progress(
    iteration: u64,
    total_iterations: u64,
    executions: u64,
    crashes: u64,
    exec_per_sec: f64,
    corpus_size: usize,
) {
    info!(
        "Progress: {}/{} ({:.1}%) | Execs: {} | Crashes: {} | Rate: {:.1} exec/s | Corpus: {}",
        iteration,
        total_iterations,
        (iteration as f64 / total_iterations as f64) * 100.0,
        executions,
        crashes,
        exec_per_sec,
        corpus_size
    );
}

pub fn log_crash_discovery(crash_id: &str, input_size: usize, error_message: Option<&str>) {
    warn!(
        "🐛 CRASH DISCOVERED! ID: {} | Input size: {} bytes | Error: {}",
        crash_id,
        input_size,
        error_message.unwrap_or("Unknown error")
    );
}

pub fn log_coverage_milestone(coverage_percentage: f64, unique_paths: usize) {
    info!(
        "📈 Coverage milestone: {:.2}% | Unique paths: {}",
        coverage_percentage,
        unique_paths
    );
}

pub fn log_session_start(protocol: &str, target: &str, workers: usize, iterations: u64) {
    info!("🚀 Starting fuzzing session:");
    info!("   Protocol: {}", protocol);
    info!("   Target: {}", target);
    info!("   Workers: {}", workers);
    info!("   Iterations: {}", iterations);
}

pub fn log_session_end(
    duration_seconds: f64,
    total_executions: u64,
    crashes_found: usize,
    final_coverage: f64,
) {
    info!("🏁 Fuzzing session completed:");
    info!("   Duration: {:.2} seconds", duration_seconds);
    info!("   Total executions: {}", total_executions);
    info!("   Crashes found: {}", crashes_found);
    info!("   Final coverage: {:.2}%", final_coverage);
    
    if crashes_found > 0 {
        warn!("⚠️  Security issues detected! Review crash reports carefully.");
    } else {
        info!("✅ No crashes detected during fuzzing session.");
    }
}

pub fn log_target_connectivity(protocol: &str, target: &str, success: bool, response_time_ms: u64) {
    if success {
        info!(
            "🌐 Target connectivity OK: {} {} ({}ms)",
            protocol, target, response_time_ms
        );
    } else {
        warn!(
            "⚠️  Target connectivity issue: {} {} ({}ms)",
            protocol, target, response_time_ms
        );
    }
}

pub fn log_corpus_seeding(protocol: &str, packets_generated: usize) {
    info!(
        "🌱 Seeded corpus for {} protocol with {} packets",
        protocol, packets_generated
    );
}

pub fn log_error(context: &str, error: &dyn std::error::Error) {
    error!("❌ {}: {}", context, error);
    
    let mut cause = error.source();
    let mut level = 1;
    while let Some(err) = cause {
        error!("   {}: {}", level, err);
        cause = err.source();
        level += 1;
    }
}