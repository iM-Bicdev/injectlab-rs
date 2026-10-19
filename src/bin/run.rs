//! The `run` CLI: score a probe set against an adapter.
//!
//! Port of `python -m injectlab.run`:
//!   run [--mock] [--list] [--json]
//!   run --openrouter MODEL [--json]
//!   run --hf MODEL [--json]
//!   run smoke [--mock | --openrouter MODEL | --hf MODEL] [--json]
//!
//! `--mock` is the default: the scripted adapter tests the harness, not a
//! model. `diff` and `lint` live in their own binaries (`rundiff`, `lint`).

use injectlab_rs::harness::{load_attack_set, run};
use injectlab_rs::models::{Adapter, HuggingFaceAdapter, MockAdapter, OpenRouterAdapter};
use injectlab_rs::pyjson::{dumps, JVal};
use injectlab_rs::smoke::smoke_test;

fn set_paths() -> (String, String) {
    let root = env!("CARGO_MANIFEST_DIR");
    (
        format!("{root}/../injectlab/attacks/attack-set-v1.4.json"),
        format!("{root}/../injectlab/attacks/control-set-v1.1.json"),
    )
}

fn usage() -> ! {
    eprintln!(
        "usage: run [--mock] [--list] [--json]\n       \
              run --openrouter MODEL [--json]\n       \
              run --hf MODEL [--json]\n       \
              run smoke [--mock | --openrouter MODEL | --hf MODEL] [--json]"
    );
    std::process::exit(2);
}

fn pick_adapter(args: &[String]) -> Adapter {
    let mut openrouter: Option<String> = None;
    let mut hf: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--openrouter" => {
                i += 1;
                if i >= args.len() {
                    usage();
                }
                openrouter = Some(args[i].clone());
            }
            "--hf" => {
                i += 1;
                if i >= args.len() {
                    usage();
                }
                hf = Some(args[i].clone());
            }
            _ => {}
        }
        i += 1;
    }
    match (openrouter, hf) {
        (Some(_), Some(_)) => {
            eprintln!("run: --openrouter and --hf are mutually exclusive");
            std::process::exit(2);
        }
        (Some(m), None) => Adapter::OpenRouter(OpenRouterAdapter::new(&m)),
        (None, Some(m)) => Adapter::HuggingFace(HuggingFaceAdapter::new(&m)),
        (None, None) => Adapter::Mock(MockAdapter::new()),
    }
}

fn run_cmd(args: &[String]) -> i32 {
    let (attack_path, control_path) = set_paths();
    let attack_set = load_attack_set(&attack_path).unwrap_or_else(|e| {
        eprintln!("run: {e}");
        std::process::exit(1);
    });
    let control_set = load_attack_set(&control_path).unwrap_or_else(|e| {
        eprintln!("run: {e}");
        std::process::exit(1);
    });

    if args.iter().any(|a| a == "--list") {
        for p in attack_set.probes.iter().chain(control_set.probes.iter()) {
            println!("{}  [{}/{}]  {}", p.id, p.category, p.severity, p.title);
        }
        return 0;
    }

    let adapter = pick_adapter(args);
    let report = run(&attack_set, &adapter, Some(&control_set));
    if args.iter().any(|a| a == "--json") {
        println!("{}", report.to_json());
    } else {
        // to_markdown() ends with "\n"; println adds the second, exactly
        // like Python's print(report.to_markdown()).
        println!("{}", report.to_markdown());
    }
    0
}

fn smoke_cmd(args: &[String]) -> i32 {
    let has_adapter_flag = args.iter().any(|a| {
        a == "--mock" || a == "--openrouter" || a == "--hf"
    });
    if !has_adapter_flag {
        eprintln!("run smoke: needs at least one adapter: --mock, --openrouter MODEL, or --hf MODEL");
        return 2;
    }
    let mut adapters: Vec<Adapter> = Vec::new();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--mock" => adapters.push(Adapter::Mock(MockAdapter::with_extra("SMOKE", "ok"))),
            "--openrouter" => {
                i += 1;
                if i >= args.len() {
                    usage();
                }
                adapters.push(Adapter::OpenRouter(OpenRouterAdapter::new(&args[i])));
            }
            "--hf" => {
                i += 1;
                if i >= args.len() {
                    usage();
                }
                adapters.push(Adapter::HuggingFace(HuggingFaceAdapter::new(&args[i])));
            }
            _ => {}
        }
        i += 1;
    }
    let results: Vec<_> = adapters.iter().map(smoke_test).collect();
    if args.iter().any(|a| a == "--json") {
        let doc = JVal::arr(results.iter().map(|r| r.to_jval()).collect());
        println!("{}", dumps(&doc));
    } else {
        for r in &results {
            println!("{}", r.to_line());
        }
    }
    if results.iter().all(|r| r.status == "ok") {
        0
    } else {
        2
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    // Reject unknown flags early instead of silently ignoring them.
    for a in &args {
        match a.as_str() {
            "--mock" | "--list" | "--json" | "--openrouter" | "--hf" | "smoke" => {}
            _ if a.starts_with('-') => {
                eprintln!("run: unknown flag {a}");
                usage();
            }
            _ => {}
        }
    }
    let code = if args.first().map(|s| s.as_str()) == Some("smoke") {
        smoke_cmd(&args[1..])
    } else {
        // A bare model name after --openrouter/--hf doesn't start with '-',
        // so it passes the filter above; anything else positional is a usage
        // error.
        let mut i = 0;
        while i < args.len() {
            if args[i] == "--openrouter" || args[i] == "--hf" {
                i += 2;
                continue;
            }
            if !args[i].starts_with('-') {
                eprintln!("run: unexpected argument {}", args[i]);
                usage();
            }
            i += 1;
        }
        run_cmd(&args)
    };
    std::process::exit(code);
}
