//! Shared fuzz target: feeds arbitrary bytes as headers + raw body into every
//! implemented provider's verification path (`spec.md` §5.6).
//!
//! Correctness is covered by the per-provider vector tests; this target exists
//! purely to assert **no panic and no timeout** on adversarial input.

#![no_main]

use libfuzzer_sys::fuzz_target;
use webhook_verify::{CustomScheme, Encoding, HashAlg, Provider, Secret, VerifyOptions};
#[cfg(feature = "sendgrid")]
use webhook_verify::VerifyingKeyMaterial;

/// Upper bound on parsed header lines so a pathological input cannot spin the
/// loop long enough to trip the fuzzer's timeout.
const MAX_HEADER_LINES: usize = 64;

/// Providers with an implementation in `src/providers/`. When a new provider
/// ships, add it here so its parsing path gets coverage too.
const IMPLEMENTED: &[Provider] = &[
    Provider::Stripe,
    Provider::GitHub,
    Provider::Shopify,
    Provider::Slack,
    Provider::Linear,
    Provider::Dropbox,
    // Square needs VerifyOptions::request_url to get past its context check
    // and into the signature path.
    Provider::Square,
    Provider::StandardWebhooks,
    // Discord's secret is a hex public key; the arbitrary-secret loop below
    // exercises its InvalidSecret decoding paths too.
    Provider::Discord,
    // Twilio is exercised separately below: it needs form-param context to
    // reach its signature path, and ignores the raw body by design.
    Provider::Twilio,
    // Zoom needs two headers (signature + timestamp) to reach its signature
    // path; timestamp-based replay is exercised via arbitrary body bytes.
    Provider::Zoom,
    // SendGrid needs `verifying_material` to get past its context check and
    // into the ECDSA/SPKI parsing path; it is additionally exercised with a
    // constant valid SPKI below.
    Provider::SendGrid,
];

/// A well-formed secret for each provider's scheme, so the fuzzer reaches the
/// signature-construction/comparison paths and not just early secret errors.
/// (Only Standard Webhooks parses its key format; the rest accept any string.)
///
/// Deliberately spelled *without* the `whsec_` prefix: the prefix is optional
/// per the Standard Webhooks spec (see `src/providers/standard_webhooks.rs`),
/// and the prefixed form's `whsec_<base64>` spelling matches GitHub's
/// Stripe-secret pattern and trips secret scanning (issue #13). Dropping the
/// prefix yields an identical decoded key.
const WELL_FORMED_SECRET: &str =
    "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=";

fn attempt(
    provider: Provider,
    headers: &dyn webhook_verify::HeaderMap,
    body: &[u8],
    secret: &str,
    options: &VerifyOptions,
) {
    let _ = webhook_verify::verify(
        provider,
        headers,
        body,
        &Secret::new(secret),
        options.clone(),
    );
}

fuzz_target!(|data: &[u8]| {
    // Input layout: `Name: value` lines, then a blank line, then the body.
    // Everything malformed stays malformed on purpose — garbage header lines
    // are exactly the input class this target exists to exercise.
    let (header_bytes, body): (&[u8], &[u8]) = match data.windows(2).position(|w| w == b"\n\n") {
        Some(pos) => (&data[..pos], &data[pos + 2..]),
        None => (data, &[]),
    };

    let mut headers: Vec<(String, String)> = Vec::new();
    for line in header_bytes.split(|&b| b == b'\n').take(MAX_HEADER_LINES) {
        let line = String::from_utf8_lossy(line);
        if let Some((name, value)) = line.split_once(':') {
            headers.push((name.trim().to_string(), value.to_string()));
        }
    }

    // URL-scoped schemes need request context to reach their signature path.
    let url_scoped_options =
        VerifyOptions::default().with_request_url("https://example.com/webhook");

    // Twilio additionally needs parsed form params; arbitrary field bytes
    // exercise its signed-string construction and base64 parsing paths.
    let twilio_options = VerifyOptions::default()
        .with_request_url("https://example.com/webhook")
        .with_form_params([
            ("CallSid", "CA1234567890ABCDE"),
            ("Digits", "1234"),
            ("From", "+14158675310"),
        ]);

    // Fail-closed dispatch for not-yet-implemented variants must also never
    // panic (Square now has an implementation; it is exercised via
    // IMPLEMENTED below, with and without its required URL context).
    attempt(Provider::Square, &headers, body, WELL_FORMED_SECRET, &url_scoped_options);
    attempt(Provider::Square, &headers, body, WELL_FORMED_SECRET, &VerifyOptions::default());
    attempt(Provider::Twilio, &headers, body, WELL_FORMED_SECRET, &twilio_options);
    attempt(Provider::Twilio, &headers, body, WELL_FORMED_SECRET, &VerifyOptions::default());

    // PayPal requires `webhook_id` + an X.509 certificate (never fetched; the
    // caller supplies it). With a constant valid test certificate, arbitrary
    // header/body bytes exercise the RFC 3339 timestamp, base64, CRC-32, and
    // RSA/X.509 parsing paths; without the context, the MissingContext
    // fail-closed path is covered.
    #[cfg(feature = "paypal")]
    {
        const PAYPAL_CERT_PEM: &[u8] = include_bytes!("../../tests/data/paypal_test_cert.pem");
        let paypal_options = VerifyOptions::default()
            .with_webhook_id("0NH55953DH663215D")
            .with_verifying_material(VerifyingKeyMaterial::X509Certificate(
                PAYPAL_CERT_PEM.to_vec(),
            ));
        attempt(Provider::PayPal, &headers, body, WELL_FORMED_SECRET, &paypal_options);
        attempt(
            Provider::PayPal,
            &headers,
            body,
            WELL_FORMED_SECRET,
            &VerifyOptions::default(),
        );
    }
    #[cfg(not(feature = "paypal"))]
    attempt(Provider::PayPal, &headers, body, WELL_FORMED_SECRET, &VerifyOptions::default());

    // SendGrid reaches its ECDSA path only with caller-supplied key material;
    // a constant valid P-256 SPKI (the provider's own vector key) lets
    // arbitrary signature/timestamp/body bytes exercise DER/SPKI parsing, and
    // the options without material exercise the MissingContext fail-closed
    // path.
    #[cfg(feature = "sendgrid")]
    {
        const SENDGRID_SPKI_DER: [u8; 91] = [
            0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06,
            0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0xf3,
            0x74, 0xf8, 0x3b, 0xf9, 0xfc, 0xe2, 0x2a, 0x2d, 0x22, 0xf2, 0x16, 0xe2, 0x67, 0x41,
            0x81, 0x0f, 0xfb, 0x74, 0x07, 0xd2, 0x9a, 0x9a, 0x88, 0x33, 0xc9, 0x05, 0xf6, 0x63,
            0x75, 0x7e, 0x5a, 0x55, 0x29, 0x2d, 0xc6, 0x46, 0xa7, 0xba, 0xda, 0x0c, 0x3e, 0xd9,
            0xf3, 0x4d, 0x45, 0xa2, 0x0d, 0x5e, 0xf5, 0x69, 0x8a, 0x09, 0x52, 0x23, 0xc7, 0x8d,
            0x11, 0xce, 0xb0, 0x10, 0x0d, 0xc5, 0xfa,
        ];
        let sendgrid_options = VerifyOptions::default().with_verifying_material(
            VerifyingKeyMaterial::EcdsaP256PublicKey(SENDGRID_SPKI_DER.to_vec()),
        );
        attempt(Provider::SendGrid, &headers, body, WELL_FORMED_SECRET, &sendgrid_options);
        attempt(Provider::SendGrid, &headers, body, WELL_FORMED_SECRET, &VerifyOptions::default());
    }
    #[cfg(not(feature = "sendgrid"))]
    attempt(Provider::SendGrid, &headers, body, WELL_FORMED_SECRET, &VerifyOptions::default());

    // CustomScheme (spec §2.2): a Slack-shaped configuration exercises the
    // prefix-strip, hex-decode, timestamp-parse, and user signed-string
    // paths with arbitrary bytes; the raw-body/base64 variant covers the
    // remaining encoding/algorithm combinations.
    let slack_like = CustomScheme {
        hash: HashAlg::Sha256,
        signature_header: "X-Slack-Signature",
        timestamp_header: Some("X-Slack-Request-Timestamp"),
        encoding: Encoding::Hex,
        prefix: Some("v0="),
        signed_string: |headers, raw_body| {
            let ts = headers.get("X-Slack-Request-Timestamp").unwrap_or_default();
            let mut signed = Vec::with_capacity(3 + ts.len() + 1 + raw_body.len());
            signed.extend_from_slice(b"v0:");
            signed.extend_from_slice(ts.as_bytes());
            signed.push(b':');
            signed.extend_from_slice(raw_body);
            signed
        },
    };
    attempt(
        Provider::Custom(slack_like),
        &headers,
        body,
        "fuzz-signing-secret",
        &VerifyOptions::default(),
    );

    let raw_b64 = |hash| CustomScheme {
        hash,
        signature_header: "X-Raw-Sig",
        timestamp_header: None,
        encoding: Encoding::Base64,
        prefix: None,
        signed_string: |_headers, raw_body| raw_body.to_vec(),
    };
    for hash in [HashAlg::Sha256, HashAlg::Sha1, HashAlg::Sha512] {
        attempt(
            Provider::Custom(raw_b64(hash)),
            &headers,
            body,
            "fuzz-signing-secret",
            &url_scoped_options.clone(),
        );
    }

    for &provider in IMPLEMENTED {
        attempt(provider, &headers, body, WELL_FORMED_SECRET, &url_scoped_options);
        // Arbitrary secret bytes exercise the key-decoding failure paths
        // (e.g. Standard Webhooks' lenient base64) without panicking.
        let arbitrary_secret = String::from_utf8_lossy(body);
        attempt(provider, &headers, body, &arbitrary_secret, &url_scoped_options);
    }
});
