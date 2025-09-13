use anyhow::Result;
use clap::{Parser, Subcommand};
use log::info;
use std::path::PathBuf;

mod fuzzer;
mod protocols;
mod coverage;
mod utils;

use fuzzer::FuzzingEngine;
use protocols::ProtocolType;

#[derive(Parser)]
#[command(name = "protocol-fuzzer")]
#[command(about = "Advanced fuzzing tool for network protocols")]
#[command(version = "0.1.0")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Fuzz a specific protocol
    Fuzz {
        /// Protocol to fuzz (dns, mqtt)
        #[arg(short, long)]
        protocol: String,
        
        /// Target host
        #[arg(short, long, default_value = "127.0.0.1")]
        target: String,
        
        /// Target port
        #[arg(short, long)]
        port: u16,
        
        /// Number of fuzzing iterations
        #[arg(short, long, default_value = "1000")]
        iterations: u64,
        
        /// Number of parallel workers
        #[arg(short, long, default_value = "4")]
        workers: usize,
        
        /// Coverage output directory
        #[arg(short, long)]
        coverage_dir: Option<PathBuf>,
        
        /// Enable verbose logging
        #[arg(short, long)]
        verbose: bool,
    },
    /// Generate test cases for a protocol
    Generate {
        /// Protocol to generate for
        #[arg(short, long)]
        protocol: String,
        
        /// Number of test cases to generate
        #[arg(short, long, default_value = "100")]
        count: usize,
        
        /// Output directory
        #[arg(short, long, default_value = "./test_cases")]
        output: PathBuf,
    },
    /// Validate protocol parsers
    Validate {
        /// Protocol to validate
        #[arg(short, long)]
        protocol: String,
        
        /// Test cases directory
        #[arg(short, long)]
        test_dir: PathBuf,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    
    // Initialize logging
    env_logger::init();
    
    info!("Starting Network Protocol Fuzzer v0.1.0");
    
    match cli.command {
        Commands::Fuzz {
            protocol,
            target,
            port,
            iterations,
            workers,
            coverage_dir,
            verbose,
        } => {
            let protocol_type = ProtocolType::from_str(&protocol)?;
            let mut engine = FuzzingEngine::new(protocol_type, target.clone(), port, workers);
            
            if let Some(coverage_dir) = coverage_dir {
                engine.enable_coverage(coverage_dir)?;
            }
            
            if verbose {
                engine.enable_verbose_logging();
            }
            
            info!("Starting fuzzing campaign for {} protocol on {}:{}", protocol, target, port);
            engine.run_fuzzing_campaign(iterations).await?;
        }
        
        Commands::Generate {
            protocol,
            count,
            output,
        } => {
            let protocol_type = ProtocolType::from_str(&protocol)?;
            info!("Generating {} test cases for {} protocol", count, protocol);
            
            fuzzer::generate_test_cases(protocol_type, count, output).await?;
        }
        
        Commands::Validate {
            protocol,
            test_dir,
        } => {
            let protocol_type = ProtocolType::from_str(&protocol)?;
            info!("Validating {} protocol parser with test cases from {:?}", protocol, test_dir);
            
            fuzzer::validate_protocol_parser(protocol_type, test_dir).await?;
        }
    }
    
    Ok(())
}
