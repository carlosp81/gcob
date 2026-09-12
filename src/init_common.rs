//! Init flags shared by the server (`gcob init`) and client
//! (`gcob-client init`) commands.
//!
//! A single definition guarantees both binaries expose identical names, help
//! text and semantics for the common options, avoiding drift between the two
//! CLIs.

use clap::Args;

/// Options common to `gcob init` and `gcob-client init`.
#[derive(Args, Debug, Clone, Default)]
pub struct CommonInitArgs {
    /// Overwrite existing files
    #[arg(long, help_heading = "Common options")]
    pub force: bool,

    /// Skip confirmation prompt (for scripting)
    #[arg(long, help_heading = "Common options")]
    pub no_confirm: bool,

    /// Hostname for the certificate (auto-detected if not specified)
    #[arg(long, help_heading = "Common options")]
    pub hostname: Option<String>,

    /// IP address for the certificate SAN (auto-detected if not specified)
    #[arg(long, help_heading = "Common options")]
    pub ip: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::{CommandFactory, Parser};

    #[derive(Parser)]
    struct TestCli {
        #[command(flatten)]
        common: CommonInitArgs,
    }

    fn parse(args: &[&str]) -> TestCli {
        TestCli::try_parse_from(args).expect("parse")
    }

    #[test]
    fn defaults_are_empty() {
        let cli = parse(&["test"]);
        assert!(!cli.common.force);
        assert!(!cli.common.no_confirm);
        assert!(cli.common.hostname.is_none());
        assert!(cli.common.ip.is_none());
    }

    #[test]
    fn parses_all_common_flags() {
        let cli = parse(&[
            "test",
            "--force",
            "--no-confirm",
            "--hostname",
            "node.example",
            "--ip",
            "10.0.0.5",
        ]);
        assert!(cli.common.force);
        assert!(cli.common.no_confirm);
        assert_eq!(cli.common.hostname.as_deref(), Some("node.example"));
        assert_eq!(cli.common.ip.as_deref(), Some("10.0.0.5"));
    }

    #[test]
    fn help_mentions_common_options() {
        let mut command = TestCli::command();
        let help = command.render_help().to_string();
        for flag in ["--force", "--no-confirm", "--hostname", "--ip"] {
            assert!(help.contains(flag), "missing {flag}: {help}");
        }
        assert!(help.contains("Common options"), "{help}");
    }
}
