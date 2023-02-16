mod logging;

use std::fs::File;
use std::io::BufReader;
use log::LevelFilter;
use vpn_libs_endpoint::core::Core;
use vpn_libs_endpoint::settings::Settings;
use vpn_libs_endpoint::shutdown::Shutdown;

const VERSION_STRING: &str = env!("CARGO_PKG_VERSION");

const VERSION_PARAM_NAME: &str = "v_e_r_s_i_o_n_do_not_change_this_name_it_will_break";
const LOG_LEVEL_PARAM_NAME: &str = "log_level";
const LOG_FILE_PARAM_NAME: &str = "log_file";
const CONFIG_PARAM_NAME: &str = "config";
const SENTRY_DSN_PARAM_NAME: &str = "sentry_dsn";


fn main() {
    let args = clap::Command::new("VPN endpoint")
        .args(&[
            // Built-in version parameter handling is deficient in that it
            // outputs `<program name> <version>` instead of just `<version>`
            // and also uses `-V` instead of `-v` as the shorthand.
            clap::Arg::new(VERSION_PARAM_NAME)
                .short('v')
                .long("version")
                .action(clap::ArgAction::SetTrue)
                .help("Print the version of this software and exit"),
            clap::Arg::new(LOG_LEVEL_PARAM_NAME)
                .short('l')
                .long("loglvl")
                .action(clap::ArgAction::Set)
                .value_parser(["info", "debug", "trace"])
                .default_value("info")
                .help("Logging level"),
            clap::Arg::new(LOG_FILE_PARAM_NAME)
                .long("logfile")
                .action(clap::ArgAction::Set)
                .help("File path for storing logs. If not specified, the logs are printed to stdout"),
            clap::Arg::new(SENTRY_DSN_PARAM_NAME)
                .long(SENTRY_DSN_PARAM_NAME)
                .action(clap::ArgAction::Set)
                .help("Sentry DSN (see https://docs.sentry.io/product/sentry-basics/dsn-explainer/ for details)"),
            clap::Arg::new(CONFIG_PARAM_NAME)
                .action(clap::ArgAction::Set)
                .required_unless_present(VERSION_PARAM_NAME)
                .help("Path to a configuration file"),
        ])
        .disable_version_flag(true)
        .get_matches();

    if args.contains_id(VERSION_PARAM_NAME)
        && Some(true) == args.get_one::<bool>(VERSION_PARAM_NAME).copied()
    {
        println!("{}", VERSION_STRING);
        return;
    }

    #[cfg(feature = "console-subscriber")]
    console_subscriber::init();

    let _guard = args.get_one::<String>(SENTRY_DSN_PARAM_NAME)
        .map(|x| sentry::init((
            x.clone(),
            sentry::ClientOptions {
                release: sentry::release_name!(),
                ..Default::default()
            }
        )));

    let _guard = logging::LogFlushGuard;
    log::set_logger(match args.get_one::<String>(LOG_FILE_PARAM_NAME) {
        None => logging::make_stdout_logger(),
        Some(file) => logging::make_file_logger(file)
            .expect("Couldn't open the logging file"),
    }).expect("Couldn't set logger");

    log::set_max_level(match args.get_one::<String>(LOG_LEVEL_PARAM_NAME).map(String::as_str) {
        None => LevelFilter::Info,
        Some("info") => LevelFilter::Info,
        Some("debug") => LevelFilter::Debug,
        Some("trace") => LevelFilter::Trace,
        Some(x) => panic!("Unexpected log level: {}", x),
    });

    let config_path = args.get_one::<String>(CONFIG_PARAM_NAME).unwrap();
    let parsed: Settings = serde_json::from_reader(BufReader::new(
        File::open(config_path).expect("Couldn't open the configuration file")
    )).expect("Failed parsing the configuration file");

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("Failed to set up runtime");

    let shutdown = Shutdown::new();
    let mut core = Core::new(parsed, shutdown.clone()).expect("Couldn't create core instance");

    rt.spawn_blocking(move || {
        core.listen().expect("Error while listening IO events");
    });

    rt.block_on(async move {
        tokio::signal::ctrl_c().await.unwrap();
        shutdown.lock().unwrap().submit();
        shutdown.lock().unwrap().completion().await;
    });
}
