mod common;
use common::*;

use std::os::unix::fs::PermissionsExt;

const SECRET: &str = "curl-secret-value-123";

fn fake_curl(f: &Fixture) -> String {
    let bin = f.path("fake-bin");
    std::fs::create_dir_all(&bin).unwrap();
    let curl = bin.join("curl");
    std::fs::write(
        &curl,
        r#"#!/bin/sh
case "$*" in
  *curl-secret-value-123*) echo ARGV_LEAK; exit 90 ;;
esac
if [ -n "${API_KEY+x}" ] || [ -n "${S_KEY+x}" ]; then
  echo ENV_LEAK
  exit 91
fi
config=
while [ "$#" -gt 0 ]; do
  if [ "$1" = "--config" ]; then
    shift
    config=$1
  fi
  shift
done
if [ -n "$config" ]; then
  cat "$config"
else
  echo NO_CONFIG
fi
"#,
    )
    .unwrap();
    std::fs::set_permissions(&curl, std::fs::Permissions::from_mode(0o755)).unwrap();
    format!("{}:/usr/bin:/bin", bin.display())
}

fn set_curl_key(f: &Fixture, domain: &str) {
    f.set("API_KEY", SECRET);
    f.s(&[
        "configure",
        domain,
        "--header",
        "Authorization: Bearer $API_KEY",
    ])
    .ok();
}

#[test]
fn configured_header_uses_unlinked_config_not_argv_or_env() {
    let f = Fixture::inited();
    set_curl_key(&f, "api.example.test");
    let path = fake_curl(&f);

    let run = f.s_env(
        &["curl", "https://api.example.test/v1/models"],
        &[("PATH", Some(&path))],
        None,
    );
    run.ok();
    let output = run.all();
    assert!(
        output.contains("header = \"Authorization: Bearer [REDACTED]\""),
        "configured header did not reach curl config: {output}"
    );
    assert!(
        !output.contains(SECRET),
        "secret escaped output scrubber: {output}"
    );
    assert!(
        !output.contains("ARGV_LEAK"),
        "secret was passed in curl argv: {output}"
    );
    assert!(
        !output.contains("ENV_LEAK"),
        "secret/control vars reached curl env: {output}"
    );

    let yaml: serde_yaml::Value = serde_yaml::from_str(&f.read_str(".senv")).unwrap();
    assert!(yaml["keys"]["API_KEY"].is_string());
    assert_eq!(
        yaml["domains"]["api.example.test"]["headers"]["Authorization"],
        "Bearer $API_KEY"
    );
}

#[test]
fn explicit_placeholder_is_substituted_in_config_and_scrubbed() {
    let f = Fixture::inited();
    set_curl_key(&f, "api.example.test");
    let path = fake_curl(&f);

    let run = f.s_env(
        &[
            "curl",
            "-H",
            "X-Token: $API_KEY",
            "--data",
            "token=${API_KEY}",
            "https://api.example.test/v1",
        ],
        &[("PATH", Some(&path))],
        None,
    );
    run.ok();
    let output = run.all();
    assert!(
        output.contains("X-Token: [REDACTED]"),
        "header substitution missing: {output}"
    );
    assert!(
        output.contains("data = \"token=[REDACTED]\""),
        "data substitution missing: {output}"
    );
    assert!(!output.contains(SECRET));
    assert!(!output.contains("ARGV_LEAK"));
}

#[test]
fn configure_updates_metadata_without_reentering_the_secret() {
    let f = Fixture::inited();
    f.set("API_KEY", SECRET);
    f.s(&[
        "configure",
        "api.example.test",
        "--header",
        "Authorization: Bearer $API_KEY",
    ])
    .ok();
    let path = fake_curl(&f);

    let run = f.s_env(
        &["curl", "https://api.example.test/v1"],
        &[("PATH", Some(&path))],
        None,
    );
    run.ok();
    assert!(run.stdout.contains("Authorization: Bearer [REDACTED]"));
}

#[test]
fn explicit_header_overrides_configured_header_without_duplication() {
    let f = Fixture::inited();
    set_curl_key(&f, "api.example.test");
    let path = fake_curl(&f);

    let run = f.s_env(
        &[
            "curl",
            "-H",
            "Authorization: Token $API_KEY",
            "https://api.example.test/v1",
        ],
        &[("PATH", Some(&path))],
        None,
    );
    run.ok();
    assert!(run.stdout.contains("Authorization: Token [REDACTED]"));
    assert_eq!(
        run.stdout.matches("Authorization:").count(),
        1,
        "configured and explicit headers were both sent: {}",
        run.stdout
    );
}
#[test]
fn wildcard_matches_subdomains_but_not_apex_or_other_hosts() {
    let f = Fixture::inited();
    set_curl_key(&f, "*.example.test");
    let path = fake_curl(&f);

    f.s_env(
        &["curl", "https://deep.api.example.test/v1"],
        &[("PATH", Some(&path))],
        None,
    )
    .ok();

    for url in ["https://example.test/v1", "https://evil.test/v1"] {
        let run = f.s_env(&["curl", url], &[("PATH", Some(&path))], None);
        run.ok();
        assert!(
            run.stdout.contains("NO_CONFIG"),
            "credential configured for {url}: {}",
            run.all()
        );
    }
}

#[test]
fn unauthorized_placeholder_and_mixed_hosts_are_refused() {
    let f = Fixture::inited();
    set_curl_key(&f, "api.example.test");

    let unauthorized = f.s(&[
        "curl",
        "-H",
        "Authorization: Bearer $API_KEY",
        "https://evil.test/v1",
    ]);
    unauthorized.fails();
    assert!(unauthorized.stderr.contains("not authorized"));
    assert!(!unauthorized.all().contains(SECRET));

    let mixed = f.s(&[
        "curl",
        "https://api.example.test/v1",
        "https://evil.test/v1",
    ]);
    mixed.fails();
    assert!(mixed.stderr.contains("mixes URLs matched and unmatched"));
}

#[test]
fn redirects_and_output_files_are_refused_with_credentials() {
    let f = Fixture::inited();
    set_curl_key(&f, "api.example.test");

    let redirect = f.s(&["curl", "-L", "https://api.example.test/v1"]);
    redirect.fails();
    assert!(redirect.stderr.contains("refuses redirects"));

    let output = f.s(&["curl", "-o", "response.json", "https://api.example.test/v1"]);
    output.fails();
    assert!(output.stderr.contains("bypass redaction"));
}

#[test]
fn insecure_tls_next_and_external_configs_are_refused() {
    let f = Fixture::inited();
    set_curl_key(&f, "api.example.test");

    for (args, message) in [
        (
            vec!["curl", "-sk", "https://api.example.test/v1"],
            "refuses --insecure",
        ),
        (
            vec![
                "curl",
                "https://api.example.test/v1",
                "--next",
                "https://api.example.test/v2",
            ],
            "refuses --next",
        ),
        (
            vec!["curl", "-sKcredentials.conf", "https://api.example.test/v1"],
            "does not accept curl config files",
        ),
    ] {
        let run = f.s(&args);
        run.fails();
        assert!(
            run.stderr.contains(message),
            "unexpected error: {}",
            run.stderr
        );
    }
}
#[test]
fn secret_transport_requires_https_except_loopback() {
    let f = Fixture::inited();
    set_curl_key(&f, "api.example.test");
    let insecure = f.s(&["curl", "http://api.example.test/v1"]);
    insecure.fails();
    assert!(insecure.stderr.contains("only over HTTPS"));
}

#[test]
fn http_is_allowed_for_localhost_and_wildcard_localhost_domains() {
    let f = Fixture::inited();
    set_curl_key(&f, "localhost");
    f.s(&[
        "configure",
        "*.localhost",
        "--header",
        "Authorization: Bearer $API_KEY",
    ])
    .ok();
    let path = fake_curl(&f);

    for url in [
        "http://localhost:8080/v1",
        "http://api.localhost:8080/v1",
        "http://deep.api.localhost:8080/v1",
    ] {
        let run = f.s_env(&["curl", url], &[("PATH", Some(&path))], None);
        run.ok();
        assert!(
            run.stdout.contains("Authorization: Bearer [REDACTED]"),
            "configured header missing for {url}: {}",
            run.all()
        );
    }
}

#[test]
fn one_key_can_use_different_headers_for_different_domains() {
    let f = Fixture::inited();
    f.set("API_KEY", SECRET);
    f.s(&[
        "configure",
        "api.one.test",
        "--header",
        "Authorization: Bearer $API_KEY",
    ])
    .ok();
    f.s(&[
        "configure",
        "api.two.test",
        "--header",
        "X-API-Key: $API_KEY",
    ])
    .ok();
    let path = fake_curl(&f);

    let one = f.s_env(
        &["curl", "https://api.one.test/v1"],
        &[("PATH", Some(&path))],
        None,
    );
    one.ok();
    assert!(one.stdout.contains("Authorization: Bearer [REDACTED]"));
    assert!(!one.stdout.contains("X-API-Key"));

    let two = f.s_env(
        &["curl", "https://api.two.test/v1"],
        &[("PATH", Some(&path))],
        None,
    );
    two.ok();
    assert!(two.stdout.contains("X-API-Key: [REDACTED]"));
    assert!(!two.stdout.contains("Authorization"));
}

#[test]
fn local_and_global_headers_merge_with_local_precedence() {
    let f = Fixture::new();
    let global = f.path(".config/senv/senv");
    let global_str = global.to_str().unwrap();
    f.s_env(&["init"], &[("S_FILE", Some(global_str))], None)
        .ok();
    f.s_env(
        &["set", "API_KEY", "--stdin"],
        &[("S_FILE", Some(global_str))],
        Some(SECRET),
    )
    .ok();
    f.s_env(
        &[
            "configure",
            "api.example.test",
            "--header",
            "Authorization: Bearer $API_KEY",
            "--header",
            "X-Scope: global",
        ],
        &[("S_FILE", Some(global_str))],
        None,
    )
    .ok();

    f.s(&["init"]).ok();
    f.s(&[
        "configure",
        "api.example.test",
        "--header",
        "X-Scope: local",
    ])
    .ok();
    let path = fake_curl(&f);
    let run = f.s_env(
        &["curl", "https://api.example.test/v1"],
        &[("S_FILE", None), ("PATH", Some(&path))],
        None,
    );
    run.ok();
    assert!(run.stdout.contains("Authorization: Bearer [REDACTED]"));
    assert!(run.stdout.contains("X-Scope: local"));
    assert!(!run.stdout.contains("X-Scope: global"));
}
