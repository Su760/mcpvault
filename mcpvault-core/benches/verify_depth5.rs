use biscuit_auth::KeyPair;
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use mcpvault_core::provider::{BiscuitProvider, TokenProvider};
use mcpvault_core::types::{AttenuateConfig, MintConfig, VerifyOptions};
use std::collections::HashSet;
use std::time::Duration;

fn build_depth5_token() -> (KeyPair, Vec<u8>) {
    let keypair = KeyPair::new();
    let provider = BiscuitProvider;

    let config = MintConfig {
        tools: Some(vec!["bench_tool".to_string()]),
        operations: vec![],
        resource_limits: vec![],
        ttl: Duration::from_secs(3600),
        max_delegation_depth: 10,
        issuer: "bench-issuer".to_string(),
        subject: "bench-agent".to_string(),
    };

    let mut token = provider.mint(&keypair, config).unwrap();

    for _ in 0..5 {
        let att = AttenuateConfig {
            tools: None,
            operations: None,
            resource_limits: None,
            ttl: None,
            max_delegation_depth: None,
        };
        token = provider.attenuate(&token, &keypair.public(), att).unwrap();
    }

    (keypair, token)
}

fn bench_verify_depth5(c: &mut Criterion) {
    let (keypair, token) = build_depth5_token();
    let provider = BiscuitProvider;
    let options = VerifyOptions {
        revocation_list: HashSet::new(),
        current_time: None,
        requested_tool: "bench_tool".to_string(),
    };

    c.bench_function("verify_depth5", |b| {
        b.iter(|| {
            provider
                .verify(
                    black_box(&token),
                    black_box(&keypair.public()),
                    black_box(options.clone()),
                )
                .unwrap()
        })
    });
}

criterion_group!(benches, bench_verify_depth5);
criterion_main!(benches);
