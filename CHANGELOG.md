# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **`Provider::from_str` now also accepts `"lexe"`** for
  [`Provider::StandardWebhooks`], matching the brand name of another signer of
  the scheme: Lexe's official sidecar webhook docs state that "Lexe's sidecar
  signs outbound webhooks using the Standard Webhooks HMAC-SHA256 scheme",
  that when a shared secret is configured every delivery carries the canonical
  `webhook-id`/`webhook-timestamp`/`webhook-signature` headers, that the
  shared secret is a random 24–64 byte string base64-encoded and
  "conventionally prefixed with `whsec_`", and that the `webhook-signature`
  value is `"v1," + base64(HMAC-SHA256(<secret>,
  "<webhook-id>.<webhook-timestamp>.<raw body>"))`
  (<https://docs.lexe.tech/sidecar/webhooks/>) — the exact Standard Webhooks
  construction this provider implements. Config files that name the provider
  by the sender's brand — `provider: lexe` — now parse to
  [`Provider::StandardWebhooks`] instead of erroring. (Alias accepted
  case-insensitively, like every other spelling. Lexe publishes no
  byte-verifiable worked example, so the test vector is recipe-built per
  `spec.md` §5.1 from their documented construction — a `payment.finalized`
  body matching their docs' example payload verbatim, with the delivery
  `webhook-id`/`webhook-timestamp` shaped from the docs' own `index`/
  `finalized_at` fields — and cross-checked in two independent HMAC-SHA256
  implementations. Source: <https://docs.lexe.tech/sidecar/webhooks/>.)
- **`Provider::from_str` now also accepts `"allo"`** for
  [`Provider::StandardWebhooks`], matching the brand name of another signer of
  the scheme: Allo's official webhook signature docs state that every delivery
  carries the canonical `webhook-id`/`webhook-timestamp`/`webhook-signature`
  (`v1,<base64>`, space-delimited during rotation) headers, that the signed
  content is the string `{webhook-id}.{webhook-timestamp}.{raw_body}`, that
  the signing secret has the `whsec_<base64key>` format with the prefix
  stripped and the remainder base64-decoded for the HMAC-SHA256 key, and that
  a ±5-minute replay window applies
  (<https://help.withallo.com/en/v2/api-reference/webhooks/verifying-signatures>) —
  the exact Standard Webhooks construction this provider implements. Config
  files that name the provider by the sender's brand — `provider: allo` — now
  parse to [`Provider::StandardWebhooks`] instead of erroring. (Alias accepted
  case-insensitively, like every other spelling. Allo publishes no byte-exact
  body/secret pair, so the test vector is recipe-built per `spec.md` §5.1 from
  their documented construction — the `webhook-id` and `webhook-timestamp`
  from their docs' worked header example and a body shaped like their
  documented `call.completed` event payload — and cross-checked in two
  independent HMAC implementations. Sources:
  <https://help.withallo.com/en/v2/api-reference/webhooks/verifying-signatures>,
  <https://help.withallo.com/en/integrations/webhooks>.)
- **`Provider::from_str` now also accepts `"acolad"`** for
  [`Provider::StandardWebhooks`], matching the brand name of another signer of
  the scheme: Acolad's official Public API webhook docs state that "The Public
  API uses a webhook service called Svix" to deliver `project.*` lifecycle
  events, that receivers are "strongly recommended" to verify every delivery,
  and that "Svix provides a number of libraries to easily verify events" plus
  manual verification instructions
  (<https://eu1.anypoint.mulesoft.com/exchange/portals/acolad/24e64f00-e5a9-4989-a410-e8cc1c143297/public-x-api/minor/2.2/pages/4u7-it6/Webhooks/>) —
  i.e. the exact Standard Webhooks construction this provider implements
  (`svix-id`/`svix-timestamp`/`svix-signature` or canonical `webhook-*`
  headers, HMAC-SHA256 over `{id}.{timestamp}.{raw_body}` keyed by the
  `whsec_`-prefixed, base64-decoded signing secret, ±5-minute replay window).
  Config files that name the provider by the sender's brand —
  `provider: acolad` — now parse to [`Provider::StandardWebhooks`] instead of
  erroring. (Alias accepted case-insensitively, like every other spelling.
  Acolad publishes no byte-exact body/secret pair, so the test vector is
  recipe-built per `spec.md` §5.1 from their documented construction and a body
  shaped like their documented `project.delivery_complete` lifecycle event, and
  cross-checked in two independent HMAC implementations. Source:
  <https://eu1.anypoint.mulesoft.com/exchange/portals/acolad/24e64f00-e5a9-4989-a410-e8cc1c143297/public-x-api/minor/2.2/pages/4u7-it6/Webhooks/>,
  <https://docs.svix.com/receiving/verifying-payloads/how-manual>.)
- **`Provider::from_str` now also accepts `"openlayer"`** for
  [`Provider::StandardWebhooks`], matching the brand name of another signer of
  the scheme: Openlayer's official webhook security docs
  (<https://docs.openlayer.com/security/webhooks/verify-signatures>) state that
  "Openlayer follows the Standard Webhooks specification", attaching the same
  `webhook-id`/`webhook-timestamp`/`webhook-signature` (`v1,<base64>`)
  headers, signing an HMAC-SHA256 over
  `{webhook-id}.{webhook-timestamp}.{raw_body}` keyed by the signing secret
  "with the `whsec_` prefix removed and the remainder Base64-decoded", with a
  ±5-minute replay window — the exact Standard Webhooks construction this
  provider implements. Config files that name the provider by the sender's
  brand — `provider: openlayer` — now parse to
  [`Provider::StandardWebhooks`] instead of erroring. (Alias accepted
  case-insensitively, like every other spelling. Openlayer publishes no
  byte-exact body/secret pair, so the test vector is recipe-built per
  `spec.md` §5.1 from their documented construction and a body shaped exactly
  like their published `test.created` example event, and cross-checked in two
  independent HMAC implementations. Source:
  <https://docs.openlayer.com/security/webhooks/verify-signatures>,
  <https://docs.openlayer.com/security/webhooks/events>.)
- **`Provider::from_str` now also accepts `"parallel"`** for
  [`Provider::StandardWebhooks`], matching the brand name of another signer of
  the scheme: Parallel's official webhook setup guide
  (<https://docs.parallel.ai/resources/webhook-setup>) states that its webhooks
  "follow standard webhook conventions", attaching the same
  `webhook-id`/`webhook-timestamp`/`webhook-signature` (`v1,<base64>`)
  headers, signing an HMAC-SHA256 over
  `{webhook-id}.{webhook-timestamp}.{payload}` keyed by the base64-decoded
  remainder of the `whsec_`-prefixed signing secret, with a space-delimited
  versioned signature list for rotation — the exact Standard Webhooks
  construction this provider implements, plus a published worked header
  example (`webhook-id: whevent_abc123def456`, `webhook-timestamp: 1751498975`,
  `webhook-signature: v1,K5oZ…`). Config files that name the provider by the
  sender's brand — `provider: parallel` — now parse to
  [`Provider::StandardWebhooks`] instead of erroring. (Alias accepted
  case-insensitively, like every other spelling. Parallel's guide also
  documents a *legacy* signing variant — the entire `whsec_…` string used raw
  as the HMAC key — still supported for earlier integrations; new deliveries
  follow the Standard Webhooks construction, and this provider verifies those.
  Parallel publishes no byte-exact body/secret pair, so the test vector is
  recipe-built per `spec.md` §5.1 from their documented construction and a body
  shaped like their Task API `task_run.status` example event, and cross-checked
  in two independent HMAC implementations. Source:
  <https://docs.parallel.ai/resources/webhook-setup>.)
- **`Provider::from_str` now also accepts `"natural"`** for
  [`Provider::StandardWebhooks`], matching the brand name of another signer of
  the scheme: Natural's official webhook integration guide
  (<https://docs.natural.co/guides/webhooks-integration>) states that "Natural
  signs every delivery with the Standard Webhooks spec", attaching the same
  `webhook-id`/`webhook-timestamp`/`webhook-signature` (`v1,<base64>`)
  headers and a signed content of `{webhook-id}.{webhook-timestamp}.{body}`
  keyed by the base64-decoded remainder of the `whsec_`-prefixed signing
  secret, with a space-delimited versioned signature list for secret rotation —
  the exact Standard Webhooks construction this provider implements. Config
  files that name the provider by the sender's brand — `provider: natural` —
  now parse to [`Provider::StandardWebhooks`] instead of erroring. (Alias
  accepted case-insensitively, like every other spelling. Natural publishes no
  byte-exact worked example, so the test vector is recipe-built per `spec.md`
  §5.1 from their documented construction and cross-checked in two independent
  HMAC implementations. Source: <https://docs.natural.co/guides/webhooks-integration>.)
- **`Provider::from_str` now also accepts `"origami"`** for
  [`Provider::StandardWebhooks`], matching the brand name of another signer of
  the scheme: Origami's official webhook docs
  (<https://docs.origami.chat/webhooks/signatures>) describe the signature as
  an "HMAC-SHA256 over the literal string
  `{webhook-id}.{webhook-timestamp}.{raw-body}` using your `whsec_…` secret as
  the HMAC key", with the prefix stripped and the remainder base64-decoded
  exactly per the canonical Standard Webhooks spec, a space-delimited `v1,`
  list for rotation, and a ±300-second replay window — the exact Standard
  Webhooks construction this provider implements. Config files that name the
  provider by the sender's brand — `provider: origami` — now parse to
  [`Provider::StandardWebhooks`] instead of erroring. (Alias accepted
  case-insensitively, like every other spelling. Origami publishes no
  byte-exact worked example, so the test vector is recipe-built per `spec.md`
  §5.1 from their documented construction and cross-checked in two independent
  HMAC implementations. Source: <https://docs.origami.chat/webhooks/signatures>.)
- **`Provider::from_str` now also accepts `"celitech"`** for
  [`Provider::StandardWebhooks`], matching the brand name of another signer of
  the scheme: CELITECH's official webhook security docs
  (<https://docs.celitech.com/webhooks/security>) state that every delivery
  carries the Svix-branded `svix-id`/`svix-timestamp`/`svix-signature`
  headers, that verification is an HMAC-SHA256 over the delivery's `svix-id`,
  `svix-timestamp`, and raw body computed with the endpoint's per-endpoint
  signing secret and compared in constant time, and that deliveries whose
  `svix-timestamp` is too far in the past or future should be rejected against
  replay attacks — the exact Standard Webhooks construction this provider
  implements. Config files that name the provider by the sender's brand —
  `provider: celitech` — now parse to [`Provider::StandardWebhooks`] instead
  of erroring. (Alias accepted case-insensitively, like every other spelling.
  CELITECH publishes no byte-exact worked example, so the test vector is
  recipe-built per `spec.md` §5.1 from their documented construction and
  cross-checked in two independent HMAC implementations. Source:
  <https://docs.celitech.com/webhooks/security>.)
- **`Provider::from_str` now also accepts `"360learning"`** for
  [`Provider::StandardWebhooks`], matching the brand name of another signer of
  the scheme: 360Learning's official webhook security docs
  (<https://360learning.readme.io/docs/security-and-signature-verification>)
  state that payloads are signed with HMAC-SHA256, that "we use Svix to deliver
  webhook events", and that each delivery carries the `webhook-id`/
  `webhook-timestamp`/`webhook-signature` (`v1,<base64>`) headers over a signed
  content of `{webhook-id}.{webhook-timestamp}.{raw_body}` — the exact Standard
  Webhooks construction this provider implements. Config files that name the
  provider by the sender's brand — `provider: 360learning` — now parse to
  [`Provider::StandardWebhooks`] instead of erroring. (Alias accepted
  case-insensitively, like every other spelling. No official byte-exact vector
  exists — 360Learning's docs worked example publishes a signature but not the
  signing secret that produced it — so the test vector is recipe-built per
  `spec.md` §5.1 from their documented construction and cross-checked in two
  independent HMAC implementations. Source:
  <https://360learning.readme.io/docs/security-and-signature-verification>.)
- **`Provider::from_str` now also accepts `"helcim"`** for
  [`Provider::StandardWebhooks`], matching the brand name of another signer of
  the scheme: Helcim's official connected-account webhooks docs
  (<https://devdocs.helcim.com/docs/connected-account-webhooks>) state that
  deliverables carry the `webhook-signature`/`webhook-timestamp`/`webhook-id`
  (`v1,<base64>`) headers, that the verification payload is
  `{webhook_id}.{webhook_timestamp}.{request_body}` signed with HMAC-SHA256
  keyed by the base64-decoded "Verifier Token" provided during onboarding, and
  that the `v1,` prefix is stripped only "if manually verifying and not using
  the SVIX library" — the exact Standard Webhooks construction this provider
  implements. Config files that name the provider by the sender's brand —
  `provider: helcim` — now parse to [`Provider::StandardWebhooks`] instead of
  erroring. (Alias accepted case-insensitively, like every other spelling. No
  official byte-exact vector exists — Helcim's docs example signs with a
  `CHANGE_ME` placeholder token — so the test vector is recipe-built per
  `spec.md` §5.1 from their documented construction and cross-checked in two
  independent HMAC implementations. Source:
  <https://devdocs.helcim.com/docs/connected-account-webhooks>.)
- **`Provider::from_str` now also accepts `"polar"`** for
  [`Provider::StandardWebhooks`], matching the brand name of another signer of
  the scheme: Polar's official webhook docs state that "Our webhook
  implementation follows the Standard Webhooks specification"
  (<https://polar.sh/docs/integrate/webhooks/endpoints>), attach the same
  `webhook-id`/`webhook-timestamp`/`webhook-signature` (`v1,<base64>`)
  headers and a signature over `{webhook-id}.{webhook-timestamp}.{body}`, and
  direct receivers to "use a Standard Webhooks library or follow the
  specification" while passing the `whsec_`-prefixed secret to that library
  as-is (<https://polar.sh/docs/integrate/webhooks/delivery>) — the exact
  Standard Webhooks construction this provider implements, with the same
  signed content and five-minute replay window enforced by Polar's own
  official SDKs. Config files that name the provider by the sender's brand —
  `provider: polar` — now parse to [`Provider::StandardWebhooks`] instead of
  erroring. (Alias accepted case-insensitively, like every other spelling.
  Sources: <https://polar.sh/docs/integrate/webhooks/delivery> and
  <https://github.com/polarsource/polar/blob/main/sdk/python/polar/webhooks.py>.)
- **`Provider::from_str` now also accepts `"daytona"`** for
  [`Provider::StandardWebhooks`], matching the brand name of another signer of
  the scheme: Daytona's official webhook docs
  (<https://www.daytona.io/docs/webhooks>) describe webhook delivery configured
  in the Daytona dashboard, and its official open-source server
  (`daytonaio/daytona`) delivers those webhooks through the Svix SDK — importing
  `{ Svix } from 'svix'`, instantiating `new Svix(authToken, { serverUrl })`,
  and calling `svix.message.create(...)` — the exact Svix-served Standard
  Webhooks construction this provider implements, and Daytona is listed as a
  Standard Webhooks-compatible sender on the official site. Config files that
  name the provider by the sender's brand — `provider: daytona` — now parse to
  [`Provider::StandardWebhooks`] instead of erroring. (Alias accepted
  case-insensitively, like every other spelling. Sources:
  <https://github.com/daytonaio/daytona/blob/46f29d5b/apps/api/src/webhook/services/webhook.service.ts>
  and <https://www.standardwebhooks.com>.)
- **`Provider::from_str` now also accepts `"crossmint"`** for
  [`Provider::StandardWebhooks`], matching the brand name of another signer of
  the scheme: Crossmint's official webhook docs state that "Crossmint signs
  every webhook and its metadata with a unique key for each endpoint", deliver
  every call with the same `svix-id`/`svix-timestamp`/`svix-signature`
  (`v1,<base64>`) headers, document signing `{svix-id}.{svix-timestamp}.{body}`
  (the raw request body) with HMAC-SHA256 keyed by the base64-decoded remainder
  of a `whsec_`-prefixed signing secret, and direct receivers to verify with
  the Svix/Standard Webhooks client libraries — the exact construction this
  provider implements, with the same reference Svix example payload its vector
  suite pins byte-for-byte. Config files that name the provider by the sender's
  brand — `provider: crossmint` — now parse to
  [`Provider::StandardWebhooks`] instead of erroring. (Alias accepted
  case-insensitively, like every other spelling. Source:
  <https://docs.crossmint.com/introduction/platform/webhooks/verify-webhooks>.)
- **`Provider::from_str` now also accepts `"novu"`** for
  [`Provider::StandardWebhooks`], matching the brand name of another signer of
  the scheme: Novu's official webhook docs state that "Novu signs webhook
  requests so you can verify that payloads were sent by Novu", attach the same
  `webhook-id`/`webhook-timestamp`/`webhook-signature` (`v1,<base64>`) headers,
  publish the reference Svix example payload as "all sent from the server", and
  direct receivers to verify with the Svix/Standard Webhooks client libraries —
  the exact construction this provider implements and the same worked example
  its vector suite pins byte-for-byte. Config files that name the provider by
  the sender's brand — `provider: novu` — now parse to
  [`Provider::StandardWebhooks`] instead of erroring. (Alias accepted
  case-insensitively, like every other spelling. Sources:
  <https://docs.novu.co/platform/developer/webhooks> and
  <https://docs.novu.co/platform/developer/webhooks/webhooks>.)
- **`Provider::from_str` now also accepts `"yoco"`** for
  [`Provider::StandardWebhooks`], matching the brand name of another signer of
  the scheme: Yoco's official webhook docs direct receivers to verify every
  delivery (its "only way to confirm an event originated from Yoco") with the
  open-source Standard Webhooks libraries and describe the exact same
  construction this provider implements — the `webhook-id`/`webhook-timestamp`/
  `webhook-signature` (`v1,<base64>`) headers, a signed-content string of
  `{webhook-id}.{webhook-timestamp}.{raw_body}`, HMAC-SHA256 keyed by the
  base64-decoded remainder of a `whsec_`-prefixed signing secret, a
  space-delimited versioned signature list, and a replay-protection timestamp
  window — and Yoco is listed as a Standard Webhooks-compatible sender on the
  official site. Config files that name the provider by the sender's brand —
  `provider: yoco` — now parse to [`Provider::StandardWebhooks`] instead of
  erroring. (Alias accepted case-insensitively, like every other spelling.
  Sources: <https://developer.yoco.com/docs/api/webhooks/verifying-events>,
  <https://yoco.docs.buildwithfern.com/docs/api/webhooks/handling-events>, and
  <https://www.standardwebhooks.com>.)
- **`Provider::from_str` now also accepts `"render"`** for
  [`Provider::StandardWebhooks`], matching the brand name of another signer of
  the scheme: Render's official webhook docs state that "Render's webhook
  implementation follows the specification defined by the Standard Webhooks
  project", attaching the same `webhook-id`/`webhook-timestamp`/
  `webhook-signature` (`v1,<base64>`) headers, an HMAC-SHA256 signature over
  `{webhook-id}.{webhook-timestamp}.{body}` keyed by the endpoint's signing
  secret, and a five-minute replay tolerance window, and direct receivers to
  verify with the Standard Webhooks client libraries — the exact construction
  this provider implements — and Render is listed as a Standard
  Webhooks-compatible sender on the official site. Config files that name the
  provider by the sender's brand — `provider: render` — now parse to
  [`Provider::StandardWebhooks`] instead of erroring. (Alias accepted
  case-insensitively, like every other spelling. Sources:
  <https://render.com/docs/webhooks> and <https://www.standardwebhooks.com>.)
- **`Provider::from_str` now also accepts `"nash"`** for
  [`Provider::StandardWebhooks`], matching the brand name of another signer of
  the scheme: Nash's official webhook docs state "We use a service called Svix
  to send webhooks" and direct receivers to verify with the Svix libraries or
  manually against the `svix-id`/`svix-timestamp`/`svix-signature` headers and
  the endpoint signing secret (Settings > Webhook Management > Signing Secret)
  — the exact Svix-served Standard Webhooks construction this provider
  implements — and Nash is listed as a Standard Webhooks-compatible sender on
  the official site. Config files that name the provider by the sender's brand —
  `provider: nash` — now parse to [`Provider::StandardWebhooks`] instead of
  erroring. (Alias accepted case-insensitively, like every other spelling.
  Sources:
  <https://docs.usenash.com/reference/webhooks>
  and <https://www.standardwebhooks.com>.)
- **`Provider::from_str` now also accepts `"drata"`** for
  [`Provider::StandardWebhooks`], matching the brand name of another signer of
  the scheme: Drata's official workflow docs state that its outbound webhook
  deliveries are sent "using Svix" — the exact Svix-served Standard Webhooks
  construction this provider implements (the `webhook-id`/
  `webhook-timestamp`/`webhook-signature` (`v1,<base64>`) headers or the Svix
  `svix-*` aliases, HMAC-SHA256 over
  `{webhook-id}.{webhook-timestamp}.{raw_body}` keyed by a `whsec_`-prefixed
  signing secret, with a five-minute replay tolerance window) — and Drata is
  listed as a Standard Webhooks-compatible sender on the official site.
  Config files that name the provider by the sender's brand —
  `provider: drata` — now parse to [`Provider::StandardWebhooks`] instead of
  erroring. (Alias accepted case-insensitively, like every other spelling.
  Sources:
  <https://help.drata.com/en/articles/11751113-automate-actions-with-drata-s-workflows>
  and <https://www.standardwebhooks.com>.)
- **`Provider::from_str` now also accepts `"inai"`** for
  [`Provider::StandardWebhooks`], matching the brand name of another signer of
  the scheme: inai's official webhook docs describe the exact same
  construction — the `webhook-id`/`webhook-timestamp`/`webhook-signature`
  (`v1,<base64>`) headers, a signed content string of
  `{webhook-id}.{webhook-timestamp}.{raw_body}`, HMAC-SHA256 keyed by the
  base64-decoded remainder of a `whsec_`-prefixed signing secret, a
  space-delimited versioned signature list, and a ±300-second replay
  tolerance window — and publish a byte-exact worked example that verifies
  against this implementation. Config files that name the provider by the
  sender's brand — `provider: inai` — now parse to
  [`Provider::StandardWebhooks`] instead of erroring. (Alias accepted
  case-insensitively, like every other spelling. Source:
  <https://docs.inai.io/docs/verifying-your-webhooks>.)
- **`Provider::StandardWebhooks` now verifies deliveries that carry the
  Svix-branded header names `svix-id`/`svix-timestamp`/`svix-signature`** in
  addition to the canonical `webhook-id`/`webhook-timestamp`/
  `webhook-signature`. Svix-hosted senders — Svix itself, Resend, Vanta,
  TaskRabbit, incident.io, ... — emit the `svix-*` names by default, and
  Svix's how-to verification docs state these "are the Svix-branded aliases
  of the spec's `webhook-*` headers; the values are identical, and the Svix
  libraries accept either set of names". Previously a genuine Svix delivery
  carrying the default `svix-*` headers failed with `MissingHeader` even
  though the provider claims Svix/Resend/Vanta coverage, so those signals are
  now verified instead of rejected. Both spellings are read
  case-insensitively; when a delivery carries both, the canonical `webhook-*`
  spelling wins deterministically and the tower/actix duplicate-header scan
  (`signature_header_names`) covers both sets. (Source:
  <https://docs.svix.com/receiving/verifying-payloads/how>.)
- **`Provider::from_str` now also accepts `"replicate"`** for
  [`Provider::StandardWebhooks`], matching the brand name of another signer of
  the scheme: Replicate's official webhook docs describe the exact same
  construction — the `webhook-id`/`webhook-timestamp`/`webhook-signature`
  (`v1,<base64>`) headers, a signed content string of
  `{webhook-id}.{webhook-timestamp}.{raw_body}`, HMAC-SHA256 keyed by the
  base64-decoded remainder of a `whsec_`-prefixed signing secret, a
  space-delimited versioned signature list, a timestamp tolerance window for
  replay protection, and a constant-time comparison recommendation. Config files
  that name the provider by the sender's brand — `provider: replicate` — now
  parse to [`Provider::StandardWebhooks`] instead of erroring. (Alias accepted
  case-insensitively, like every other spelling. Source:
  <https://replicate.com/docs/topics/webhooks/verify-webhook>.)
- **`Provider::from_str` now also accepts `"flip"`** for
  [`Provider::StandardWebhooks`], matching the brand name of another signer of
  the scheme: Flip Energy's official webhook docs state that its deliveries
  "follow the Standard Webhooks specification", describing the exact same
  construction — the `webhook-id`/`webhook-timestamp`/`webhook-signature`
  (`v1,<base64>`) headers, a signed content string of
  `{webhook-id}.{webhook-timestamp}.{raw_body}`, HMAC-SHA256 keyed by the
  base64-decoded remainder of a `whsec_`-prefixed signing secret, a five-minute
  replay tolerance window, and a constant-time comparison recommendation. Config
  files that name the provider by the sender's brand — `provider: flip` — now
  parse to [`Provider::StandardWebhooks`] instead of erroring. (Alias accepted
  case-insensitively, like every other spelling. Source:
  <https://docs.flip.energy/oem/webhooks>.)
- **`Provider::from_str` now also accepts `"liveblocks"`** for
  [`Provider::StandardWebhooks`], matching the brand name of another signer of
  the scheme: Liveblocks' official webhook docs describe the exact same
  construction — the `webhook-id`/`webhook-timestamp`/`webhook-signature`
  (`v1,<base64>`) headers, a signed content string of
  `{webhook-id}.{webhook-timestamp}.{raw_body}`, HMAC-SHA256 keyed by the
  base64-decoded remainder of a `whsec_`-prefixed signing secret, a
  space-delimited versioned signature list, a five-minute replay tolerance
  window, and a constant-time comparison recommendation — directing receivers
  to the Svix end-to-end tooling. Config files that name the provider by the
  sender's brand — `provider: liveblocks` — now parse to
  [`Provider::StandardWebhooks`] instead of erroring. (Alias accepted
  case-insensitively, like every other spelling. Source:
  <https://liveblocks.io/docs/platform/webhooks>.)
- **`Provider::from_str` now also accepts `"taskrabbit"`** for
  [`Provider::StandardWebhooks`], matching the brand name of another signer of
  the scheme: TaskRabbit's official webhook docs state that its deliveries are
  "delivered via Svix" and that "Svix signs every webhook payload with a secret
  key unique to your endpoint", directing receivers to verify the signature
  with the Svix/Standard Webhooks libraries and to discard unverified
  webhooks; TaskRabbit is also listed as a Standard Webhooks-compatible sender
  on the [official site](https://www.standardwebhooks.com). Config files that
  name the provider by the sender's brand — `provider: taskrabbit` — now parse
  to [`Provider::StandardWebhooks`] instead of erroring. (Alias accepted
  case-insensitively, like every other spelling. Source:
  <https://developer.taskrabbit.com/docs/webhooks>.)
- **`Provider::from_str` now also accepts `"prescience"`** for
  [`Provider::StandardWebhooks`], matching the brand name of another signer of
  the scheme: Prescience's official webhook docs state that signatures "follow
  the [standard-webhooks](https://www.standardwebhooks.com) scheme", describe
  the exact same construction — the canonical
  `webhook-id`/`webhook-timestamp`/`webhook-signature` (`v1,<base64>`) headers,
  a signed content string of `{webhook-id}.{webhook-timestamp}.{raw_body}`,
  HMAC-SHA256 keyed by the base64-decoded remainder of a `whsec_`-prefixed
  signing secret, constant-time comparison, and a ~5-minute replay tolerance
  window — and publish a byte-exact worked example whose claimed signature is
  the genuine HMAC of the example (verified, not just asserted). Config files
  that name the provider by the sender's brand — `provider: prescience` — now
  parse to [`Provider::StandardWebhooks`] instead of erroring. (Alias accepted
  case-insensitively, like every other spelling. Source:
  <https://docs.getprescience.com/guides/webhooks>.)
- **`Provider::from_str` now also accepts `"safetykit"`** for
  [`Provider::StandardWebhooks`], matching the brand name of another signer of
  the scheme: SafetyKit's official webhook docs describe the exact same
  construction — the canonical `webhook-id`/`webhook-timestamp`/
  `webhook-signature` (`v1,<base64>`) headers, a signed content string of
  `{webhook-id}.{webhook-timestamp}.{raw_body}`, HMAC-SHA256 keyed by the
  base64-decoded remainder of a `whsec_`-prefixed signing secret, a
  space-delimited `v1,` signature list, a five-minute replay tolerance
  window, and a constant-time comparison recommendation — and direct receivers
  to verify with the Svix/Standard Webhooks client libraries. Config files
  that name the provider by the sender's brand — `provider: safetykit` — now
  parse to [`Provider::StandardWebhooks`] instead of erroring. (Alias accepted
  case-insensitively, like every other spelling. Source:
  <https://docs.safetykit.com/webhooks/verifying-signatures>.)
- **`Provider::from_str` now also accepts `"vanta"`** for
  [`Provider::StandardWebhooks`], matching the brand name of another major
  signer of the scheme: Vanta's official webhook docs state that its event
  deliveries are "powered by Svix", carry the `svix-id`/`svix-timestamp`/
  `svix-signature` headers (the Svix-branded aliases of the spec's
  `webhook-*` names), and verify with a `{svix-id}.{svix-timestamp}.
  {raw_body}` signed content, HMAC-SHA256 keyed by the base64-decoded
  remainder of a `whsec_`-prefixed signing secret, a space-delimited `v1,`
  signature list, and a five-minute replay tolerance window. Config files
  that name the provider by the sender's brand — `provider: vanta` — now
  parse to [`Provider::StandardWebhooks`] instead of erroring. (Alias
  accepted case-insensitively, like every other spelling. Sources:
  <https://developer.vanta.com/docs/webhooks> and
  <https://www.standardwebhooks.com>.)
- **`Provider::from_str` now also accepts `"zapier"`** for
  [`Provider::StandardWebhooks`], matching the brand name of another major
  signer of the scheme: Zapier's official webhook docs state that its
  connection-webhook deliveries follow the Standard Webhooks specification,
  attach the canonical `webhook-id`/`webhook-timestamp`/`webhook-signature`
  (`v1,<base64>`) headers, sign a message built by concatenating the id,
  timestamp, and exact raw payload with `.` joins using HMAC-SHA256 keyed by
  the endpoint's `whsec_`-prefixed signing secret, recommend rejecting
  deliveries outside a five-minute timestamp window, and direct receivers to
  verify with the reference Standard Webhooks libraries. Config files that
  name the provider by the sender's brand — `provider: zapier` — now parse to
  [`Provider::StandardWebhooks`] instead of erroring. (Alias accepted
  case-insensitively, like every other spelling. Source:
  <https://docs.zapier.com/white-label/connection-webhooks/verify-signatures>.)
- **`Provider::from_str` now also accepts `"dodo"` (and `"dodopayments"`)** for
  [`Provider::StandardWebhooks`], matching the brand name of another major
  signer of the scheme: Dodo Payments' official webhook docs state that its
  deliveries follow the Standard Webhooks specification, attach the same
  `webhook-id`/`webhook-timestamp`/`webhook-signature` (`v1,<base64>`) headers,
  sign a message built by concatenating the id, timestamp, and exact raw
  payload with `.` joins using HMAC-SHA256 keyed by the endpoint's signing
  secret, and direct receivers to verify with the reference Standard Webhooks
  libraries. Config files that name the provider by the sender's brand —
  `provider: dodo` — now parse to [`Provider::StandardWebhooks`] instead of
  erroring. (Alias accepted case-insensitively, like every other spelling.
  Source: <https://docs.dodopayments.com/developer-resources/webhooks>.)
- **`Provider::from_str` now also accepts `"sardine"`** for
  [`Provider::StandardWebhooks`], matching the brand name of another major
  signer of the scheme: Sardine's official webhook docs describe the exact
  same construction — the `webhook-id`/`webhook-timestamp`/`webhook-signature`
  (`v1,<base64>`) headers, a signed content string of
  `{webhook-id}.{webhook-timestamp}.{raw_body}`, HMAC-SHA256 keyed by the
  base64-decoded remainder of a `whsec_`-prefixed signing secret, and a
  constant-time comparison recommendation. Sardine is also listed as a
  Standard Webhooks-compatible sender on the official site. Config files
  that name the provider by the sender's brand — `provider: sardine` — now
  parse to [`Provider::StandardWebhooks`] instead of erroring. (Alias
  accepted case-insensitively, like every other spelling. Sources:
  <https://docs.payments.sardine.ai/integration_guides/nft_checkout/webhooks>
  and <https://www.standardwebhooks.com>.)
- **`Provider::from_str` now also accepts `"etsy"`** for
  [`Provider::StandardWebhooks`], matching the brand name of another major
  signer of the scheme: Etsy's official webhook docs describe the exact same
  construction — the `webhook-id`/`webhook-timestamp`/`webhook-signature`
  (`v1,<base64>`) headers, a signed content string of
  `{webhook-id}.{webhook-timestamp}.{raw_body}`, HMAC-SHA256 keyed by the
  base64-decoded remainder of a `whsec_`-prefixed signing secret, and a
  300-second replay tolerance window. Etsy is also listed as a Standard
  Webhooks-compatible sender on the official site. Config files that name
  the provider by the sender's brand — `provider: etsy` — now parse to
  [`Provider::StandardWebhooks`] instead of erroring. (Alias accepted
  case-insensitively, like every other spelling. Sources:
  <https://developers.etsy.com/documentation/essentials/webhooks> and
  <https://www.standardwebhooks.com>.)
- **`Provider::from_str` now also accepts `"supabase"`** for
  [`Provider::StandardWebhooks`], matching the brand name of another major
  signer of the scheme: Supabase's official auth-hooks docs state that HTTP
  hooks "follow the Standard Webhooks Specification", attach the same three
  `webhook-id`/`webhook-timestamp`/`webhook-signature` (`v1,<base64>`)
  headers, generate symmetric `v1,whsec_<base64-secret>` signing secrets,
  and direct receivers to verify with the reference Standard Webhooks
  libraries. Supabase is also listed as a Standard Webhooks-compatible
  sender on the official site. Config files that name the provider by the
  sender's brand — `provider: supabase` — now parse to
  [`Provider::StandardWebhooks`] instead of erroring. (Alias accepted
  case-insensitively, like every other spelling. Sources:
  <https://supabase.com/docs/guides/auth/auth-hooks> and
  <https://www.standardwebhooks.com>.)
- **`Provider::from_str` now also accepts `"incident.io"`** (and the short
  `"incident"` spelling) for [`Provider::StandardWebhooks`], matching the
  brand name of another signer of the scheme: incident.io's official
  webhook docs state that its deliveries are "powered by Svix", carry the
  three Standard Webhooks headers (`webhook-id`/`webhook-timestamp`/
  `webhook-signature` with a `v1,<base64>` signature), describe the
  signature as an HMAC of `$WEBHOOK_ID.$WEBHOOK_TIMESTAMP.$REQUEST_BODY`
  keyed by the endpoint's signing secret, and direct receivers to verify
  with the Svix/Standard Webhooks client libraries. incident.io is also
  listed as a Standard Webhooks-compatible sender on the official site.
  Config files that name the provider by the sender's brand —
  `provider: incident.io` — now parse to [`Provider::StandardWebhooks`]
  instead of erroring. (Alias accepted case-insensitively, like every other
  spelling. Sources: <https://docs.incident.io/integrations/webhooks> and
  <https://www.standardwebhooks.com>.)
- **`Provider::from_str` now also accepts `"lithic"`** for
  [`Provider::StandardWebhooks`], matching the brand name of another major
  signer of the scheme: Lithic's official events API docs describe the exact
  Standard Webhooks construction this crate verifies — the
  `webhook-id`/`webhook-timestamp`/`webhook-signature` (`v1,<base64>`)
  headers, HMAC-SHA256 over `{webhook-id}.{webhook-timestamp}.{raw_body}`
  keyed by the base64 part of a `whsec_`-prefixed signing secret, a
  space-delimited versioned signature list, and a five-minute replay
  tolerance window. Lithic's published byte-exact worked example is now a
  test vector for this provider. Config files that name the provider by the
  sender's brand — `provider: lithic` — now parse to
  [`Provider::StandardWebhooks`] instead of erroring. (Alias accepted
  case-insensitively, like every other spelling. Source:
  <https://docs.lithic.com/docs/events-api>.)
- **`Provider::from_str` now also accepts `"bigcommerce"`** (and the
  human-readable `"big commerce"`/`"big-commerce"` spellings, like the other
  multi-word aliases) for [`Provider::StandardWebhooks`], matching the brand
  name of a major signer of the scheme: BigCommerce's official webhook docs
  direct merchants to verify callback events with the official Standard
  Webhooks libraries — "We advise merchants to use libraries provided by
  Standard Webhook to verify the legitimacy of the events" — and show
  `wh.verify(webhook_payload, webhook_headers)` over the exact
  `webhook-id`/`webhook-timestamp`/`webhook-signature` (`v1,<base64>`)
  construction this crate verifies, keyed by the base64-encoded client
  secret, with a signature plus a "timestamp used to protect against replay
  attacks". Config files that name the provider by the sender's brand —
  `provider: bigcommerce` — now parse to [`Provider::StandardWebhooks`]
  instead of erroring. (Alias accepted case-insensitively, like every other
  spelling. Source:
  <https://docs.bigcommerce.com/developer/docs/integrations/webhooks/https>.)
- **`Provider::from_str` now also accepts `"brex"`** for
  [`Provider::StandardWebhooks`], matching the brand name of another major
  signer of the scheme: Brex's official webhook docs describe the exact
  Standard Webhooks construction this crate verifies — `webhook-id` /
  `webhook-timestamp` / `webhook-signature` (`v1,<base64>`) headers,
  HMAC-SHA256 over `{webhook-id}.{webhook-timestamp}.{raw_body}` keyed by a
  base64-decoded signing secret, and a space-delimited versioned signature
  list — and list Brex as a Standard Webhooks-compatible sender on the
  official site. Brex's published byte-exact test vector is now a test vector
  for this provider. Config files that name the provider by the sender's brand
  — `provider: brex` — now parse to [`Provider::StandardWebhooks`] instead of
  erroring. (Alias accepted case-insensitively, like every other spelling.
  Sources: <https://developer.brex.com/guides/webhooks> and
  <https://www.standardwebhooks.com>.)
- **`Provider::from_str` now also accepts `"gemini"`** for
  [`Provider::StandardWebhooks`], matching the brand name of one of the
  biggest signers of the scheme: Google Gemini's official webhook docs state
  that static webhook deliveries "strictly follow the Standard Webhooks
  specification for security headers", signing every delivery with the
  Standard Webhooks `webhook-id` / `webhook-timestamp` / `webhook-signature`
  (`v1,<base64>`) construction keyed by a `whsec_`-prefixed signing secret
  returned by the WebhookService API, and recommend verifying with the
  reference Standard Webhooks libraries. Config files that name the provider
  by the sender's brand — `provider: gemini` — now parse to
  [`Provider::StandardWebhooks`] instead of erroring. (Alias accepted
  case-insensitively, like every other spelling. Source:
  <https://ai.google.dev/gemini-api/docs/webhooks>.)
- **`Provider::from_str` now also accepts `"anthropic"`** for
  [`Provider::StandardWebhooks`], matching the brand name of one of the
  biggest signers of the scheme: Anthropic's webhook documentation states that
  every delivery carries the Standard Webhooks `webhook-id` /
  `webhook-timestamp` / `webhook-signature` (`v1,<base64>`) construction and a
  32-byte `whsec_`-prefixed signing secret, and its SDK verifies deliveries
  with the reference Standard Webhooks verifier. Config files that name the
  provider by the sender's brand — `provider: anthropic` — now parse to
  [`Provider::StandardWebhooks`] instead of erroring. (Alias accepted
  case-insensitively, like every other spelling. Source:
  <https://platform.claude.com/docs/en/managed-agents/webhooks>.)
- **`Provider::from_str` now also accepts `"loops"`** for
  [`Provider::StandardWebhooks`], matching the brand name of a provider whose
  official webhook documentation ships a verification snippet using the exact
  Standard Webhooks construction the provider already verifies: canonical
  `webhook-id` / `webhook-timestamp` / `webhook-signature` (`v1,<base64>`)
  headers, a `whsec_`-prefixed base64 signing secret, HMAC-SHA256 over
  `"{id}.{timestamp}.{raw_body}"`, a 300-second tolerance window, and a
  space-delimited signature list for zero-downtime secret rotation. Config
  files that name the provider by the sender's brand — `provider: loops` —
  now parse to [`Provider::StandardWebhooks`] instead of erroring. (Alias
  accepted case-insensitively, like every other spelling. Source:
  <https://loops.so/docs/webhooks>.)
- **`Provider::from_str` now also accepts `"warp"`** for
  [`Provider::StandardWebhooks`], matching the brand name of a provider whose
  webhook documentation states it "implements the Standard Webhooks
  specification": every delivery carries the same `webhook-id` /
  `webhook-timestamp` / `webhook-signature` (`v1,<base64>`) construction and
  `whsec_`-prefixed signing secret the provider already verifies, and the docs
  explicitly recommend verifying with the reference Standard Webhooks
  libraries. Config files that name the provider by the sender's brand —
  `provider: warp` — now parse to [`Provider::StandardWebhooks`] instead of
  erroring. (Alias accepted case-insensitively, like every other spelling.
  Source:
  <https://docs.warp.co/webhooks>.)
- **`Provider::from_str` now also accepts `"openai"`** for
  [`Provider::StandardWebhooks`], matching the brand name of one of the
  biggest signers of the scheme: OpenAI's webhook documentation states its
  deliveries "follow the Standard Webhooks specification", and shows every
  delivery signed with the same `webhook-id` / `webhook-timestamp` /
  `webhook-signature` (`v1,<base64>`) construction and `whsec_`-prefixed
  signing secret the provider already verifies, explicitly recommending the
  reference Standard Webhooks libraries for verification. Config files that
  name the provider by the sender's brand — `provider: openai` — now parse
  to [`Provider::StandardWebhooks`] instead of erroring. (Alias accepted
  case-insensitively, like every other spelling. Source:
  <https://developers.openai.com/api/docs/guides/webhooks>.)
- **`Provider::from_str` now also accepts `"gitlab"`** for
  [`Provider::StandardWebhooks`], matching the brand name of one of the
  biggest signers of the scheme: GitLab's webhook documentation states its
  delivery "follows the Standard Webhooks specification" and, when a
  "signing token" is configured (the recommended authentication mode since
  GitLab 19.0), signs every request with the same `webhook-id` /
  `webhook-timestamp` / `webhook-signature` (`v1,<base64>`) construction and
  `whsec_`-prefixed secret the provider already verifies. Config files that
  name the provider by the sender's brand — `provider: gitlab` — now parse
  to [`Provider::StandardWebhooks`] instead of erroring. (Alias accepted
  case-insensitively, like every other spelling; GitLab's legacy plaintext
  `secret token` (`X-Gitlab-Token`) mode is intentionally *not* covered —
  it offers no signature to verify.)
- **`Provider::from_str` now also accepts `"clerk"`** for
  [`Provider::StandardWebhooks`], matching the brand name of one of the
  largest signers of the scheme: Clerk's official backend SDK maps the Svix
  header names (`svix-id`/`svix-timestamp`/`svix-signature`) onto the
  Standard Webhooks header names and verifies deliveries with the reference
  Standard Webhooks verifier, keyed by the `whsec_` signing secret from the
  Clerk Dashboard. Config files that name the provider by the sender's brand —
  `provider: clerk` — now parse to [`Provider::StandardWebhooks`] instead of
  erroring. (Alias accepted case-insensitively, like every other spelling.
  Source:
  <https://github.com/clerk/javascript/blob/main/packages/backend/src/webhooks.ts>.)
- **New provider: `Webflow`** (`Provider::Webflow`). Verifies the hex
  HMAC-SHA256 in `x-webflow-signature`, whose signed string joins the
  `x-webflow-timestamp` value — Unix epoch **milliseconds**, parsed to an
  integer and reformatted to its canonical decimal form exactly as Webflow's
  reference verifiers do (`parseInt(timestamp, 10)` in Node, `int(timestamp)`
  in Python) — with the raw request body through a literal `:` separator, no
  other delimiters. The docs warn to verify against "the exact bytes of the
  request body" before deserializing, matching the crate's `raw_body`
  contract. Keying is the webhook's signing key used verbatim as its UTF-8
  bytes (never decoded): a per-webhook site token secret for webhooks created
  through site settings, or the OAuth application's client secret for OAuth-
  created webhooks. The docs prescribe a 300000ms (~5 minute) freshness
  window, so the shared symmetric `max_age` replay window (default 300s)
  applies after the millisecond value is floored to whole seconds (as with
  WorkOS, Airwallex, and HubSpot); the timestamp is HMAC-covered, so an
  attacker cannot freshen it. Scheme and test-vector provenance linked to
  <https://developers.webflow.com/data/docs/working-with-webhooks> in
  `spec.md` §3. `Provider::from_str` accepts `"webflow"`.
- **New provider: `Recharge`** (`Provider::Recharge`). Verifies the hex digest
  in the `X-Recharge-Hmac-Sha256` header, which — despite the header name — is
  a **plain SHA-256** of the per-token **API Client Secret's** UTF-8 bytes
  concatenated with the raw request body (secret first, no separator), not an
  HMAC; the four reference recipes in Recharge's "Validating webhooks" docs
  (OpenSSL, Python, PHP, Ruby) all agree on the bare-digest construction. The
  docs warn the body "must be in JSON string format. Validation will fail even
  if one space is lost" and that the reverse concatenation order "will result
  in fake false", matching the crate's `raw_body` contract (never re-serialize)
  and a secret-prepended signed string. It is the crate's only non-HMAC
  shared-secret scheme and routes through the new audited shared
  `verify_sha256_prepended_key` helper in `src/core/crypto.rs` (a strictly
  additive core change: no existing code is touched, only Recharge consumes
  it). No timestamp is signed, so `max_age` has no effect and replay
  protection cannot be provided at the signature layer; the docs' newer
  timestamp-signed format has no official description or vector yet and is
  explicitly out of scope. Scheme and test-vector provenance linked to
  <https://docs.getrecharge.com/docs/webhooks-overview> in `spec.md` §3.
  `Provider::from_str` accepts `"recharge"`.
- **New provider: `Airwallex`** (`Provider::Airwallex`). Verifies the hex
  HMAC-SHA256 in `x-signature`, whose signed string concatenates the
  `x-timestamp` value (epoch **milliseconds**, as sent) directly with the raw
  request body — no separators — keyed by the notification URL's secret used
  verbatim as its UTF-8 bytes (never decoded). The docs warn to verify against
  the original unmodified body before any JSON parsing, matching the crate's
  `raw_body` contract. Airwallex leaves the freshness tolerance to the caller,
  so the shared symmetric `max_age` replay window (default 300s) applies after
  the millisecond timestamp is floored to whole seconds (as with WorkOS and
  HubSpot); `x-signature` is only sent on subscriptions configured with a
  secret. Scheme and test-vector provenance linked to
  <https://www.airwallex.com/docs/developer-tools/webhooks/listen-for-webhook-events>
  in `spec.md` §3. `Provider::from_str` accepts `"airwallex"`.
- **New provider: `Mollie`** (next-gen webhooks; `Provider::Mollie`). Verifies
  the hex HMAC-SHA256 over the raw body in the `X-Mollie-Signature` header
  behind a literal `sha256=` prefix (matched case-sensitively, exactly like
  GitHub), keyed by the signing secret configured at webhook setup used
  verbatim as its UTF-8 bytes (never decoded). Mollie's docs instruct
  verifying against "the unaltered POST body", matching the crate's
  `raw_body` contract. No timestamp is signed, so `max_age` has no effect.
  During the documented 24-hour rotation window Mollie attaches **two**
  `X-Mollie-Signature` headers per event; this crate reads the first, so
  rotating callers keep the previous secret until the window closes and
  verify against each. Only next-gen signed webhooks are covered — classic
  `webhookUrl` deliveries POST a bare `id=<resource_id>` form field and are
  unsigned. Scheme and test-vector provenance linked to
  <https://docs.mollie.com/reference/webhooks-new> and Mollie's official SDKs
  in `spec.md` §3. `Provider::from_str` accepts `"mollie"`.
- **New provider: `FastSpring`** (`Provider::FastSpring`). Verifies the bare
  base64 HMAC-SHA256 over the raw body in the `X-FS-Signature` header, keyed
  by the per-webhook "HMAC SHA256 Secret" — the same shape as Tally, Shopify,
  Xero, and WooCommerce. The signing secret is optional: when the webhook's
  secret field is left blank, FastSpring sends unsigned requests. FastSpring's
  docs warn the header may arrive with varying case (lookup is
  case-insensitive) and note that payloads must be verified before any JSON
  parsing (raw-body signing, matching the crate's `raw_body` contract). No
  timestamp is signed, so `max_age` has no effect. Scheme and test-vector
  provenance linked to <https://developer.fastspring.com/reference/message-security>
  in `spec.md` §3. `Provider::from_str` accepts `"fastspring"`.
- **New provider: `GoCardless`** (`Provider::GoCardless`). Verifies the bare
  lowercase-hex HMAC-SHA256 over the raw body in the `Webhook-Signature`
  header, keyed by the webhook endpoint secret used verbatim as its UTF-8
  bytes (never decoded — the secret merely looks base64url-shaped). No
  timestamp is signed, so `max_age` has no effect; GoCardless's docs mandate
  hashing the raw request body without re-parsing, matching the crate's
  `raw_body` contract. Scheme and test-vector provenance linked to
  <https://docs.gocardless.com/docs/api-reference/webhooks> in `spec.md` §3.
  `Provider::from_str` accepts `"gocardless"`.
- **New provider: `Tailscale`**. Verifies the hex HMAC-SHA256 in
  `Tailscale-Webhook-Signature`, a comma-separated `t=<unix_ts>,v1=<hex>`
  list. The signed string is `{t}.{raw_body}` keyed by the per-endpoint
  webhook secret; the docs recommend a five-minute replay window, so the
  shared symmetric `max_age` (default 300s) applies. Multiple `v1=` values
  are accepted during secret rotation, and unknown fields/schemes are
  discarded. Scheme and test-vector provenance linked to
  <https://tailscale.com/docs/features/webhooks> and Tailscale's official
  example verifier
  (<https://github.com/tailscale/tailscale/blob/main/docs/webhooks/example.go>)
  in `spec.md` §3.
- **`Provider::from_str` now also accepts `"resend"` and `"svix"`** for
  [`Provider::StandardWebhooks`], matching the brand names of two of its
  biggest signers (Resend and Svix both deliver via the Standard Webhooks /
  `svix-*` construction with a `whsec_`-shaped secret). Config files that
  name the provider by its signer's brand — `provider: resend` /
  `provider: svix` — now parse instead of erroring. (Alias accepted
  case-insensitively, like every other spelling; the original
  `"standardwebhooks"` / `"standard webhooks"` spellings are unchanged.)
- **`Provider::from_str` now also accepts `"messagebird"` and `"bird"`** for
  [`Provider::StandardWebhooks`], matching the brand names of Bird (formerly
  MessageBird), whose webhook documentation states its deliveries "follow the
  Standard Webhooks specification" (headers `webhook-id` /
  `webhook-timestamp` / `webhook-signature` with `v1,<base64>` signatures and
  a `whsec_`-prefixed signing secret). Config files that name the provider by
  the sender's brand — `provider: bird` / `provider: messagebird` — now parse
  to [`Provider::StandardWebhooks`] instead of erroring. (Alias accepted
  case-insensitively, like every other spelling.)
- **New provider: `Contentful`** (webhooks with a configured signing secret).
  Verifies the hex HMAC-SHA256 in `x-contentful-signature`, reconstructed over
  Contentful's documented canonical string
  `[method, requestPath, signedHeaders, body].join('\n')` where the signed
  header names/order come from the self-describing `x-contentful-signed-headers`
  list, with replay protection over the epoch-milliseconds
  `x-contentful-timestamp`. Requires `VerifyOptions::request_method` and
  `request_url`. Scheme and test-vector provenance linked to
  <https://www.contentful.com/developers/docs/webhooks/request-verification/>,
  `@contentful/node-apps-toolkit`, and
  contentful-labs/request-verification-examples in `spec.md` §3.

- **`Provider::from_str` now accepts the hyphenated and space-separated
  multi-word spellings** operators write in config files and the current
  brand name of the formerly-Mandrill provider:
  `"hub-spot"`/`"hub spot"` → `HubSpot`,
  `"launch-darkly"`/`"launch darkly"` → `LaunchDarkly`,
  `"lemon-squeezy"` → `LemonSqueezy`,
  `"pager-duty"`/`"pager duty"` → `PagerDuty`,
  `"woo-commerce"`/`"woo commerce"` → `WooCommerce`,
  `"standard-webhooks"` → `StandardWebhooks`, and
  `"mailchimp"`/`"mailchimp-transactional"`/`"mailchimp transactional"` →
  `Mandrill` (Mailchimp Transactional is the name this crate's docs/README
  use for that provider). Parsing stays case-insensitive and the original compact forms (`"hubspot"`, `"standardwebhooks"`, ...) keep
  working; `"custom"` still requires a `CustomScheme` and is rejected as a bare
  name.

- **New provider: Expo (EAS)** (`Provider::Expo`): hex **HMAC-SHA1** over the
  exact request body, keyed by the webhook signing secret (the `--secret`
  value chosen with `eas webhook:create`, which Expo requires to be at least
  16 characters) as its UTF-8 bytes, delivered in `expo-signature` behind a
  literal `sha1=` prefix — the same `sha1=`-prefixed shape as Intercom's
  `X-Hub-Signature`. Covers EAS Build and EAS Submit webhook deliveries.
  Expo's reference verification sample feeds the exact body text
  (`bodyParser.text({ type: '*/*' })` then `hmac.update(req.body)`) into a
  constant-time comparison, so the crate hashes `raw_body` verbatim. No
  timestamp is signed, so `max_age` has no effect. Like Twilio, Intercom, and
  Vercel, Expo still legitimately mandates SHA-1: the HMAC is keyed with the
  shared secret, which is immune to SHA-1's collision attacks. Expo documents
  the construction and ships reference verification code but publishes no
  byte-exact example signature, so the vectors are locally constructed over
  exactly the documented recipe (the primary vector's body mirrors the shape
  of the docs' build-payload example), cross-checked with OpenSSL and Python's
  `hmac`. Source:
  <https://docs.expo.dev/eas/webhooks/> (source: `expo/expo`,
  `docs/pages/eas/webhooks.mdx`).

- **New provider: Ripple (Collections)** (`Provider::Ripple`): hex
  HMAC-SHA256 over a **double-hash** signed string —
  `{timestamp}.{sha256(raw_body)}` — where `timestamp` is the
  `X-Webhook-Timestamp` epoch-milliseconds value reused *verbatim* as the `t=`
  element of the `X-Webhook-Signature` header (the docs require both to match
  verbatim, and `t` must equal the timestamp header byte-for-byte or the
  request is rejected as malformed). The key is Ripple's
  `signature_verification_key`, **base64-decoded** once with a single strict
  standard-base64 decode before keying the HMAC (a double-base64-encoded
  secret is Ripple's documented first signature-mismatch pitfall). The
  timestamp is HMAC-covered and routes through the shared `max_age` replay
  window after the documented millisecond floored-to-seconds step (`> 1e12`
  → divide by 1000, exactly as Ripple's reference verifier does). Ripple
  documents the recipe and ships a reference Python verifier but publishes no
  byte-exact example signature, so the vectors are locally constructed over
  exactly the documented construction (a Collections-style `payment.completed`
  body mirroring the docs' event shape), cross-checked with OpenSSL and
  Python's `hashlib`/`hmac`. Source:
  <https://docs.ripple.com/products/collections/guides/verifying-webhooks>
  ("Verifying Webhooks").

- **New provider: X (formerly Twitter)** (`Provider::X`): base64
  HMAC-SHA256 over the exact request body, keyed by the app's **consumer
  secret** (the "API secret key" — never the bearer or access token) as its
  UTF-8 bytes and delivered in `x-twitter-webhooks-signature` behind a
  literal `sha256=` prefix, mirroring GitHub's prefix handling. X's docs warn
  that re-encoding or deserializing the body breaks the signature, so the
  crate hashes `raw_body` verbatim. No timestamp is signed, so `max_age` has
  no effect; the Challenge-Response Check's `response_token` shares the exact
  same construction over `crc_token` (a response the caller computes, so this
  crate covers the delivery header only). `from_str` accepts `"x"` plus the
  legacy pre-rebrand spellings `"twitter"`, `"x twitter"`, and `"x-twitter"`
  (case-insensitive). X documents the scheme and ships reference HMAC code but
  publishes no byte-exact example signature, so the vectors are locally
  constructed over exactly the documented recipe, cross-checked with OpenSSL
  and Python's `hmac`; the primary vector's body mirrors the shape of X's
  documented `tweet_create_event` example. Source:
  <https://docs.x.com/x-api/account-activity/guides/account-activity-webhooks>
  ("Securing webhooks").

- **New provider: Fintoc** (`Provider::Fintoc`): **hex** HMAC-SHA256 over the
  raw request body prefixed by a literal dot and the `t` Unix-seconds value
  *exactly as sent* — `{t}.{raw_body}` — with the `t`/`v1` fields riding in
  the single `Fintoc-Signature` header (`t=...,v1=...` comma list). Fintoc's
  docs are explicit that the raw, unparsed request body must be used
  ("Libraries can represent parsed JSON differently"), so the crate hashes
  `raw_body` verbatim. The timestamp is HMAC-covered and routes through the
  shared `max_age` replay window, matching Fintoc's documented five-minute
  tolerance. Fintoc documents the scheme and publishes an example header
  (`t=1620870928,v1=4df951e0...f567f6d`) and an example signed message
  (`1626102791.{"id":"evt_DyzYBwdC07ao5MqG",...}`) but no byte-exact
  signature, so the vectors are locally constructed over exactly the
  documented recipe — the primary vector's body and timestamp are the docs'
  own example message — cross-checked with OpenSSL and Python's `hmac`; the
  docs' published example header is replayed as a well-formed-but-mismatching
  input. Sources:
  <https://docs.fintoc.com/docs/webhooks-validating> ("Validate webhook
  signatures") and the official
  [fintoc-node](https://github.com/fintoc-com/fintoc-node) /
  [fintoc-python](https://github.com/fintoc-com/fintoc-python) SDKs'
  `WebhookSignature` verifiers.

- **New provider: LINE Messaging API** (`Provider::Line`): **base64**
  HMAC-SHA256 over the exact request body, keyed by the channel secret as its
  UTF-8 bytes and delivered in `x-line-signature`. LINE's docs are explicit
  that any modification of the body string — deserialization, JSON
  formatting, escape-character interpretation, encoding changes — breaks the
  signature, so the crate hashes `raw_body` verbatim like Shopify/Dropbox/
  DocuSign. No timestamp is signed, so `max_age` has no effect. The primary
  test vector is the byte-exact example LINE publishes on its
  "Verify webhook signature" page (body, channel secret, and signature all
  given there); the boundary vectors are locally constructed over the same
  documented recipe, cross-checked with OpenSSL and Python's `hmac`. Source:
  <https://developers.line.biz/en/docs/messaging-api/verify-webhook-signature/>
  ("Verify webhook signature").
- **New provider: Mailchimp Transactional** (`Provider::Mandrill`,
  formerly Mandrill): base64 **HMAC-SHA1** over the webhook URL (exactly as
  configured, including any query string) followed by each `POST` form
  field's name and value concatenated with no delimiter — `{url}{key1}{value1}...`
  — the field names sorted alphabetically, delivered in `X-Mandrill-Signature`.
  Like Twilio, the scheme covers the parsed form fields (`mandrill_events`, a
  JSON array of batched events, historically the only field) rather than the
  raw body, so callers pass the URL in `VerifyOptions::request_url` and every
  received field via `VerifyOptions::form_params`; omitting either fails
  closed with `MissingContext`. Mailchimp's official guide is explicit that
  only base64 works ("using a hexadecimal signature will not work"), and the
  SHA-1-HTMLMAC note from Twilio applies: the HMAC is keyed with the shared
  webhook authentication key, which is immune to SHA-1's collision attacks.
  No timestamp is signed, so `max_age` has no effect. The main vector
  reproduces the guide's webhook-URL-check scenario (`mandrill_events=[]`
  signed with the documented generic key `test-webhook`); Mailchimp publishes
  the construction and reference code but no byte-exact example signature, so
  the vectors are locally constructed over exactly the documented recipe,
  cross-checked with OpenSSL. Sources:
  <https://mailchimp.com/developer/transactional/guides/track-respond-activity-webhooks/>
  ("Authenticating webhook requests") and the Node.js `generateSignature`
  reference implementation in the same guide.
- **New provider: Box** (`Provider::Box`): HMAC-SHA256 over
  `{raw_body}{delivery_timestamp}`, **base64**-encoded and delivered in two
  headers — `BOX-SIGNATURE-PRIMARY` and `BOX-SIGNATURE-SECONDARY`. Box signs
  every delivery with both configured keys, so a delivery verifies when
  **either** header matches the caller's single `Secret` (rotation-safe);
  both headers are required, and the signed `BOX-DELIVERY-TIMESTAMP`
  (RFC 3339) makes the shared `max_age` replay window apply. The optional
  `BOX-SIGNATURE-VERSION`/`BOX-SIGNATURE-ALGORITHM` metadata is validated
  only when present. The byte-exact vectors come from Box's Java SDK
  reference test (`WebhookValidationTest`); note the secrets it actually keys
  with are `SamplePrimaryKey`/`SampleSecondaryKey`, not the keys the docs
  display on developer.box.com. Sources:
  <https://developer.box.com/guides/webhooks/v2/signatures-v2> and
  <https://github.com/box/box-java-sdk/blob/main/doc/webhooks.md>.
- **New provider: Pusher Channels** (`Provider::Pusher`): HMAC-SHA256 over
  the raw POST body, **hex**-encoded, delivered bare (no prefix, no
  timestamp) in the `X-Pusher-Signature` header. The signing key is the
  **secret** of the Pusher app token named in the `X-Pusher-Key` header —
  the key value itself is not part of the signed content, it only selects
  which token's secret keys the HMAC; callers with multiple active tokens
  must pass the secret of the one the delivery was signed with (Pusher
  rotates tokens, so verifying oldest-active first matches the docs). No
  timestamp is signed, so the shared `max_age` replay window has no effect
  (`spec.md` §3). Sources:
  <https://pusher.com/docs/channels/server_api/webhooks> ("The signature is
  generated using the POST body with the token's secret") and Pusher's
  official PHP reference implementation
  (<https://github.com/pusher/pusher-http-php/blob/main/src/Webhook.php>:
  `hash_hmac("sha256", $body, $app_secret, false)`). Pusher publishes the
  construction but no byte-exact example body+signature pair, so the vectors
  are locally constructed over exactly the documented construction, cross-checked
  with OpenSSL; the 32-byte digest length is pinned by the length-reject case.
- **New provider: Vercel** (`Provider::Vercel`): HMAC-SHA1 over the raw
  request body, **hex**-encoded, delivered bare (no `sha1=` prefix, no
  timestamp) in the `x-vercel-signature` header. The signing key is the webhook
  secret shown when creating an account webhook, or the Integration Secret
  (Client Secret) for integration webhooks, used verbatim as its UTF-8 bytes.
  Covers requests from Webhooks, Log Drains, and integration webhooks alike.
  Vercel is one of the built-in providers' four SHA-1 schemes (with Twilio,
  Intercom, and Expo EAS), and the only bare-hex raw-body one — like Twilio
  and Intercom, the HMAC is keyed with the shared secret, which is immune to
  SHA-1's collision attacks. No timestamp is
  signed, so the shared `max_age` replay window has no effect. Sources:
  <https://vercel.com/docs/webhooks/webhooks-api> ("Securing webhooks") and
  <https://vercel.com/docs/headers/request-headers#x-vercel-signature> (the
  latter states the header "contains an HMAC-SHA1 signature" and ships a
  reference verifier that compares `digest('hex')` output to the header with
  `crypto.timingSafeEqual`). Vercel publishes the construction and full
  reference code but no byte-exact example signature, so the vectors are
  locally constructed over exactly the documented construction, cross-checked
  across OpenSSL and Python; the SHA-256-length reject case pins the 20-byte
  digest shape.
- **New provider: DocuSign** (`Provider::DocuSign`): Connect's HMAC-SHA256
  over the raw request body, **base64**-encoded (standard alphabet with
  padding), delivered bare (no prefix, no timestamp) in the
  `X-Docusign-Signature-1` header. The signing key is the Connect
  configuration's HMAC key, used verbatim as its UTF-8 bytes. DocuSign sends
  one numbered header per configured key (`-1`, `-2`, ... up to 100) and
  accepts a match against any of them; this provider verifies the first key's
  header (`-1`), which ships on every delivery and is the recommended
  single-key setup — numbered headers beyond `-1` are intentionally out of
  scope for the crate's single-header model (`spec.md` §3). No timestamp is
  signed, so the shared `max_age` replay window has no effect. Sources:
  <https://developers.docusign.com/platform/webhooks/connect/validate/>
  ("How to validate an HMAC signature" — raw-body / line-endings signing rule
  and base64 encoding),
  <https://developers.docusign.com/platform/webhooks/connect/hmac/>
  (one numbered header per key), and the official PHP verification sample
  (<https://www.docusign.com/blog/developers/hmac-verification-php>).
  DocuSign publishes the algorithm and reference code but no byte-exact
  example body+signature pair, so the vectors are locally constructed over
  exactly the documented construction and cross-checked against both OpenSSL
  and Python's `hmac` module (two independent implementations).
- **New provider: Intercom** (`Provider::Intercom`): HMAC-SHA1 over the raw
  request body, **hex**-encoded with a literal `sha1=` prefix, delivered
  case-sensitively in the `X-Hub-Signature` header (40 hex characters / 20
  bytes). The signing key is the Intercom app's `client_secret` (Developer Hub
  → Basic Info), used verbatim as its UTF-8 bytes. Intercom is, like Twilio, a
  scheme that still legitimately mandates SHA-1 — the HMAC is keyed with the
  shared secret, which is immune to SHA-1's collision attacks. No timestamp is
  signed, so the shared `max_age` replay window has no effect (`spec.md` §3).
  Source:
  <https://developers.intercom.com/docs/references/2.5/webhooks/webhook-models>
  ("Signing notifications"). Intercom publishes the header format and an
  example header value but no byte-exact signed body, so the vectors are
  locally constructed over exactly the documented construction
  (`sha1=` + lowercase hex of `HMAC-SHA1(client_secret, raw_body)`), cross-checked
  across OpenSSL and Python; the 20-byte digest length is pinned by the length
  reject case.
- **New provider: Meta** (`Provider::Meta`): HMAC-SHA256 over the raw
  request body, **hex**-encoded with a `sha256=` prefix, delivered case-
  sensitively in the `X-Hub-Signature-256` header. The signing key is the
  app's **App Secret** (App Dashboard → Basic), used verbatim as its UTF-8
  bytes — the same construction as GitHub's `X-Hub-Signature-256` but keyed
  with Meta's App Secret. Covers Graph API webhooks (Facebook Pages, Messenger,
  Instagram) and WhatsApp Cloud API deliveries alike. Meta signs the payload's
  escaped-unicode serialization, so callers must pass the untouched request
  bytes; for ASCII-only JSON the two encodings are byte-identical. No timestamp
  is signed, so the shared `max_age` replay window has no effect. Sources:
  <https://developers.facebook.com/docs/graph-api/webhooks/getting-started>
  ("Validating payloads"), the WhatsApp Cloud API endpoint walkthrough
  (<https://developers.facebook.com/documentation/business-messaging/whatsapp/webhooks/create-webhook-endpoint>),
  and the Messenger Platform reference (`verifyRequestSignature`). Meta
  publishes the header format and an example header value but no byte-exact
  signed body (the App Secret is account-specific), so the vectors are locally
  constructed over exactly the documented construction (`sha256=` + lowercase
  hex of `HMAC-SHA256(app_secret, raw_body)`), cross-checked across OpenSSL
  and Python.
- **New provider: Paystack** (`Provider::Paystack`): HMAC-SHA512 over the raw
  request body, **hex**-encoded, delivered bare (no prefix, no timestamp) in
  the `x-paystack-signature` header. The signing key is the Paystack secret key
  from the dashboard ("Settings → API Keys & Webhooks"), used verbatim as its
  UTF-8 bytes. Paystack is the built-in providers' only HMAC-SHA512 scheme —
  it exercises the shared `verify_hmac_sha512` helper that `CustomScheme`
  previously used alone. No timestamp is signed, so the shared `max_age` replay
  window has no effect (the docs recommend IP allow-listing as a complement,
  which is a deployment concern outside this crate's scope). Source:
  <https://paystack.com/docs/payments/webhooks/> ("Verify event origin →
  Signature validation"). Paystack publishes no byte-exact example signature,
  so the vectors are locally constructed over exactly the documented
  construction, cross-checked across OpenSSL and Python; the 
  SHA-256-length reject case pins the 64-byte digest shape.
- **New provider: Klaviyo** (`Provider::Klaviyo`): HMAC-SHA256 over
  `{raw_body}{timestamp}` — the `Klaviyo-Timestamp` header value exactly as
  sent (IMF-fixdate / RFC 1123, e.g. `Thu, 04 Jan 2024 18:05:25 GMT`)
  concatenated after the raw body bytes, no separator — hex-encoded and
  delivered bare (no `sha256=` prefix) in the `Klaviyo-Signature` header. The
  signing secret is used verbatim as its UTF-8 bytes (Klaviyo's reference
  code never decodes it); the signed timestamp enables the shared symmetric
  `max_age` replay window via a new strict IMF-fixdate parser in
  `src/core/replay.rs` (weekday checked against the date, leap-year-aware,
  no non-`GMT` zones, no leap-second `:60` — RFC 3339 spellings and
  two-digit-year variants fail closed). `Klaviyo-Webhook-Id` is not part of
  the HMAC and is intentionally not verified (binding it requires
  deserializing the body). Source:
  <https://developers.klaviyo.com/en/docs/working_with_system_webhooks>
  ("Working with system webhooks"). Klaviyo publishes an example delivery but
  no body or signing key, so the vectors are locally constructed over exactly
  the documented construction, cross-checked with OpenSSL; the published
  example delivery is replayed as a well-formed-but-mismatching input.
- **New provider: Calendly** (`Provider::Calendly`): HMAC-SHA256 over
  `{t}.{raw_body}`, hex-encoded, delivered in the `Calendly-Webhook-Signature`
  header as a comma-separated `t=<unix_ts>,v1=<hex_hmac>` list. The `t`
  timestamp rides verbatim into the signed string and enables the shared
  symmetric `max_age` replay window (Calendly's docs demonstrate a 180-second
  tolerance; the crate default is 300s and callers can match the documented
  zone with `with_max_age`). Duplicate `t`/`v1` elements are rejected as
  ambiguous (`spec.md` §4.4) — Calendly documents no rotation list, so a second
  `v1=` is malformed rather than rotation — and unknown elements are ignored for
  forward compatibility. Source:
  <https://developer.calendly.com/api-docs/overview/webhooks/webhook-signatures>
  ("Webhook Signatures"). Calendly publishes an example header but no body or
  signing key, so the vectors are locally constructed over exactly the
  documented construction, cross-checked across OpenSSL and Python; the
  published example header is replayed as a well-formed-but-mismatching input.
- **New provider: WooCommerce** (`Provider::WooCommerce`): HMAC-SHA256 over
  the raw request body, **base64**-encoded (standard alphabet with padding,
  not hex — the same bug class as Shopify/Xero), delivered in the
  `X-WC-Webhook-Signature` header. The webhook's configured `secret` is used
  verbatim as its UTF-8 bytes (never decoded). No timestamp is signed, so the
  shared `max_age` replay window has no effect for this provider (WooCommerce
  recommends deduping on the payload's own `id`). Sources:
  <https://developer.woocommerce.com/docs/apis/rest-api/v3/webhooks> (the
  delivery-header reference: "X-WC-Webhook-Signature - a base64 encoded
  HMAC-SHA256 hash of the payload") and the `WC_Webhook::generate_signature`
  reference implementation
  (<https://woocommerce.github.io/code-reference/classes/WC-Webhook.html>).
  WooCommerce publishes no byte-exact example signature, so the vectors are
  locally constructed over exactly the documented construction, cross-checked
  with OpenSSL.
- **New provider: WorkOS** (`Provider::WorkOS`): HMAC-SHA256 over
  `{t}.{raw_body}`, hex-encoded, delivered in the `WorkOS-Signature` header as
  a comma-separated `t=<epoch_ms>,v1=<hex_hmac>` list. The `t` timestamp is in
  epoch **milliseconds** and rides verbatim into the signed string (sub-second
  digits included), then is floored to whole seconds for the shared symmetric
  `max_age` replay window (WorkOS's SDKs take the tolerance in seconds, "usually
  3–5 minutes"). Duplicate `t`/`v1` elements are rejected as ambiguous
  (`spec.md` §4.4); unknown elements are ignored for forward compatibility.
  Source: <https://workos.com/docs/events/data-syncing/webhooks> ("Sync data
  with webhooks" — manual-verification section), corroborated by the official
  SDK verifiers (`workos-go`'s `WebhookVerifier`) and the SDK reference
  (`workos-workos-node.mintlify.app/api/webhooks`). WorkOS publishes no
  byte-exact example signature, so the vectors are locally constructed over
  exactly the documented construction with a non-round millisecond timestamp
  (exercising the sub-second truncation boundary), cross-checked with OpenSSL.
- **New provider: LaunchDarkly** (`Provider::LaunchDarkly`): HMAC-SHA256 over
  the raw body bytes, hex-encoded and delivered bare (no `sha256=` prefix) in
  the `X-LD-Signature` header. The signing secret configured on the
  integration is used verbatim (its UTF-8 bytes) as the HMAC key — LaunchDarkly
  never decodes or re-encodes it. No timestamp is signed, so the shared
  `max_age` replay window has no effect for this provider (LaunchDarkly itself
  recommends reordering deliveries by the payload's own `date` field). Sources:
  <https://launchdarkly.com/docs/home/infrastructure/webhooks> and
  <https://launchdarkly.com/docs/api/webhooks>. LaunchDarkly publishes no
  byte-exact example signature, so the vectors are locally constructed over
  exactly the documented construction, cross-checked with OpenSSL.
- **New provider: Zendesk** (`Provider::Zendesk`): HMAC-SHA256 over
  `{timestamp}{raw_body}` — the `X-Zendesk-Webhook-Signature-Timestamp` header
  value exactly as sent (RFC 3339) concatenated with the raw body bytes, no
  separator — base64-encoded and delivered bare (no `sha256=` prefix) in the
  `X-Zendesk-Webhook-Signature` header. The signing secret is used verbatim as
  the HMAC key (Zendesk's reference code never decodes it); the signed
  timestamp enables the shared symmetric `max_age` replay window. Source:
  <https://developer.zendesk.com/documentation/webhooks/verifying>
  ("Verifying webhook authenticity"), corroborated by
  <https://developer.zendesk.com/documentation/webhooks/anatomy-of-a-webhook-request>.
  Zendesk publishes no byte-exact example signature, so the vectors are locally
  constructed over exactly the documented construction using Zendesk's own
  static test-webhook secret, cross-checked across OpenSSL and Python.
- **New provider: Mux** (`Provider::Mux`): HMAC-SHA256 over `{t}.{raw_body}`,
  hex-encoded, delivered in the `Mux-Signature` header as a comma-separated
  `t=<unix_ts>,v1=<hex_hmac>` list. Multiple `v1=` values are accepted during
  signing-secret rotation (a match on any is accepted), matching Mux's
  official SDKs, and the signed timestamp enables the shared symmetric
  `max_age` replay window (Mux's SDKs use a 300s tolerance). Sources:
  <https://www.mux.com/docs/core/verify-webhook-signatures>, the official
  Elixir verifier
  (<https://github.com/muxinc/mux-elixir/blob/master/lib/mux/webhooks.ex>),
  and the official Node verifier
  (<https://github.com/muxinc/mux-node-sdk/blob/main/src/resources/webhooks/webhooks.ts>);
  the primary test vector is Mux's own published vector from its SDK test
  utilities (<https://hexdocs.pm/mux/Mux.Webhooks.TestUtils.html>).
- **New provider: Adyen** (`Provider::Adyen`): HMAC-SHA256 over the raw body,
  base64-encoded, delivered in the `HmacSignature` header (header lookup is
  case-insensitive, so the docs' lowercase `hmacsignature` also resolves) with
  no timestamp or replay window. The Customer Area HMAC key is a hex string and
  is hex-decoded to raw key bytes, matching Adyen's official Java/Go libraries;
  a non-hex or empty key fails closed. Covers Adyen's header-based scheme
  (Adyen for Platforms / Banking, Management API, classic-platform
  notifications); Standard payments webhooks, whose signature lives inside the
  JSON body, are intentionally not covered. Sources:
  <https://docs.adyen.com/development-resources/webhooks/secure-webhooks/verify-hmac-signatures>
  and
  <https://docs.adyen.com/classic-platforms/configure-notifications/signing-notifications-with-hmac>
  (whose worked example is reproduced byte-for-byte as the test vector).
- **New provider: PagerDuty v3 webhooks** (`Provider::PagerDuty`): HMAC-SHA256
  over the raw body, hex-encoded, delivered in the `X-PagerDuty-Signature`
  header as one or more comma-separated `v1=<hex_hmac>` values (matching
  PagerDuty's key-rotation list format) with no timestamp or replay window.
  Non-`v1` elements are discarded per the official SDK's downgrade protection;
  an empty `v1=` value, non-hex, or wrong-length signature fails closed. Source:
  <https://developer.pagerduty.com/docs/verifying-signatures> and the official
  Go SDK's `webhookv3` package, whose published test vectors
  (<https://github.com/PagerDuty/go-pagerduty/blob/main/webhookv3/webhookv3_test.go>)
  are reproduced byte-for-byte.
- **New provider: Twitch EventSub** (`Provider::Twitch`): HMAC-SHA256 over
  the concatenation of the `Twitch-Eventsub-Message-Id` header, the
  `Twitch-Eventsub-Message-Timestamp` header (RFC 3339, used verbatim), and
  the raw body, hex-encoded, delivered in the
  `Twitch-Eventsub-Message-Signature` header as `sha256=<hex_hmac>`. The
  signed timestamp also enables the shared symmetric `max_age` replay window.
  Source:
  <https://dev.twitch.tv/docs/eventsub/handling-webhook-events/>.
- **New provider: Bitbucket Cloud** (`Provider::Bitbucket`): HMAC-SHA256 over
  the raw body, hex-encoded, delivered in the `X-Hub-Signature` header as
  `sha256=<hex_hmac>` (the WebSub `method=signature` format) with no timestamp
  or replay window. The exact `sha256=` prefix is matched case-sensitively,
  mirroring GitHub; an unknown `method` fails closed instead of being
  mis-verified. Source:
  <https://support.atlassian.com/bitbucket-cloud/docs/manage-webhooks/>.
- **New provider: Sentry** (`Provider::Sentry`): HMAC-SHA256 over the raw
  body, bare hex-encoded, delivered in the `Sentry-Hook-Signature` header,
  keyed by the integration's Client Secret, with no timestamp or replay
  window. Covers Sentry's Integration Platform webhooks. Source:
  <https://docs.sentry.io/integrations/integration-platform/webhooks>.
- **New provider: Razorpay** (`Provider::Razorpay`): HMAC-SHA256 over the raw
  body, bare hex-encoded, delivered in the `X-Razorpay-Signature` header with
  no timestamp or replay window. Source:
  <https://razorpay.com/docs/webhooks/validate-test/> and maintainer-published
  worked examples in <https://github.com/razorpay/razorpay-node/issues/29>.
- A seed corpus for the `parse_and_verify` fuzz target
  (`fuzz/corpus/parse_and_verify/`): the CI nightly run now starts from the
  crate's own published test vectors (GitHub, Slack, Stripe, Discord, Dropbox,
  Razorpay, Sentry,
  Standard Webhooks, HubSpot, Zoom, Paddle, Cloudflare, Coinbase, Notion,
  Square, Xero, Linear, Shopify, LemonSqueezy, Typeform, Twitch, PagerDuty,
  Adyen) plus an adversarial malformed input, so
  libFuzzer spends
  its 600s budget mutating around known-good delivery shapes instead of
  rediscovering the header/body input layout from an empty input. Seeds are
  repo-local only — the `/fuzz` package is excluded from the crates.io
  tarball.
- **New provider: Typeform** (`Provider::Typeform`): HMAC-SHA256 over the
  raw body, base64-encoded, delivered in the `Typeform-Signature` header as
  `sha256=<base64_hmac>` with no timestamp or replay window. Source:
  <https://developers.typeform.com/developers/webhooks/secure-your-webhooks/>.
- **New provider: Lemon Squeezy** (`Provider::LemonSqueezy`): HMAC-SHA256 over
  the raw body, bare hex-encoded, delivered in the `X-Signature` header with
  no timestamp or replay window. Source:
  <https://docs.lemonsqueezy.com/help/webhooks/signing-requests>.
- [`Secret`](crate::Secret) now derives `PartialEq`, `Eq`, and `Hash`. This
  is the one remaining caller-facing key-material type lacking the equality
  contract that `VerifyError`/`ProviderParseError`/`VerifyingKeyMaterial`
  already expose ("complete the `Eq` contract", see the entry below), so
  rotated secrets can now be compared and deduplicated in
  `HashSet`/`HashMap` bookkeeping without the inner value becoming readable —
  the redacted `Debug`/`Display` behavior, `Default`, and all constructors
  are unchanged. Equality hashes/compares the wrapped key bytes directly and
  is verified by tests to stay in lockstep with `Hash`.
- `VerifyError`, `ProviderParseError`, and `VerifyingKeyMaterial` now derive
  `Hash`, completing the `Eq` contract those types already expose. Callers can
  now derive `Hash` on their own types containing them and use them in
  `HashSet`/`HashMap` contexts (e.g. deduplicating logged failures). `Hash` is
  consistent with each type's `PartialEq` — verified by new tests, including a
  pinning test that the hand-written `CustomScheme::hash` stays in lockstep
  with its declarative `PartialEq` (`signed_string` excluded from both).
- [`HeaderMap`](crate::HeaderMap) is now implemented for borrowed-key maps
  (`BTreeMap<&str, &str>`, and `HashMap<&str, &str>` behind the `std`
  feature), so static header tables built from `&'static str` pairs verify
  directly without allocating owned keys — the map counterpart of the
  existing `Vec<(&str, &str)>`/slice impls. Same case-insensitive lookup and
  same first-match semantics as the owned-key forms, with the same
  inherent-`get` shadowing caveat (call `HeaderMap::get(&map, name)`).
  Spec.md §2's blanket-impl list updated.
- CI now build-checks the `no_std + alloc` guarantee against a genuinely
  std-less target: the `no-std-riscv` job builds `cargo build --no-default-features
  --target riscv32imac-unknown-none-elf` (pure core) and `cargo build
  --no-default-features --features sendgrid --target
  riscv32imac-unknown-none-elf` (core + the one genuinely no_std-compatible
  feature). The previous wasm32 gate ships std and could not prove a std-less
  build; `riscv32imac-unknown-none-elf` is a bare-metal target with no
  standard library, closing the gap between the spec.md §7 claim and CI
  enforcement.
- CI now gates the crates.io tarball with a `cargo package --all-features` job
  (`package`). `cargo package` verifies two things no other job checks: the
  packaged **file list** stays free of tracked debris that would ship
  verbatim in the tarball (the regression class that shipped
  `probe_ci_write_test.yml` earlier — nothing checked the tarball contents),
  and the packaged tree compiles with every feature from a clean extract, so
  a feature-gated module that builds in-repo but would fail for a crates.io
  consumer is caught pre-merge instead of at first release. Previously this
  was a manual `cargo package` step in the README's releasing flow only.
- The Standard Webhooks provider's test module now covers the §5.5
  garbage-value case for the opaque `webhook-id` header: a non-id-shaped
  value is pinned as well-formed (verified against a signature made over it)
  rather than a malformed header, and a signature over the real id cannot be
  swapped in (the id feeds the signed string verbatim).
- The combined `key=value` signature headers (Stripe, Paddle, Coinbase,
  Cloudflare) now tolerate whitespace after the element separator: keys are
  compared after trimming, so the comma-space/semicolon-space spelling real
  integrations emit (`t=..., v1=...`, `ts=...; h1=...`, `time=..., sig1=...`,
  `t=..., v0=...`) parses exactly like the canonical form instead of being
  silently dropped into a misleading "missing `t` field" failure. Values are
  never trimmed — timestamps still ride verbatim into the signed string, so
  verification strength is unchanged (spec §3 rows updated).
- The tower (`VerifyLayer`) and actix (`WebhookConfig`) adapters now reject a
  request whose declared `Content-Length` already exceeds
  `with_max_body_size` with `413 Payload Too Large` *before* any body bytes
  are buffered, closing the "bounds work, not memory" gap for
  content-length-bearing requests. Bodies sent without a length
  (`Transfer-Encoding: chunked`) fall through to the existing post-buffer
  check, which still bounds the signature work.
- The `http` feature is now correctly documented as **std-bounded in practice**:
  the `http` crate itself requires `std` (its own `lib.rs` emits
  `compile_error!("std feature currently required...")` when built without it),
  so a genuinely std-less build cannot include the `http` feature — the same
  class of dependency-forced `std` as `paypal` (issue #23, `spec.md` §3).
  The README, spec §6, and spec §7 `no_std` scope record now reflect this
  honestly; the `no_std + alloc` guarantee is core + `sendgrid` only.
- The `test-nostd` `http` CI run (`cargo test --no-default-features
  --features http`) is now correctly framed: it exercises the crate's own
  `http::HeaderMap` impl with the crate's own `std` feature off (a behavioral
  catch for the crate's own code), but cannot prove a std-less build because
  the `http` crate ships `std` regardless. The wasm32 build gate (issue #25)
  now build-checks both `sendgrid,paypal` and `http` feature sets for
  `--target wasm32-unknown-unknown` (parity with the `test-nostd` matrix);
  the `.github/workflows/ci.yml` hunk shipped in PR #26.
- The `test-nostd` and `doc` CI jobs ship in `.github/workflows/ci.yml`,
  retiring the earlier "CI wiring pending — blocked on the runner token's
  missing `workflows` permission" notes (issues #18/#22): the `no_std`
  behavioral test runs and the `RUSTDOCFLAGS="-D warnings"` doc build are now
  enforced by CI itself, not just the local contributor gates.
- The `cargo-audit` dependency-vulnerability scan ships in
  `.github/workflows/ci.yml` as an informational (non-blocking) job against
  the RustSec advisory database (PR #30). The fuzz target build is now
  covered by the `Fuzz` workflow on every PR and master push (build-only;
  timed runs stay nightly), so the duplicate `fuzz-build` job is retired from
  `ci.yml`.
- HubSpot webhook provider (v3 scheme) — HMAC-SHA256 over
  `{method}{uri}{raw_body}{timestamp}`, base64-encoded,
  `X-HubSpot-Signature-V3` with the `X-HubSpot-Request-Timestamp` header
  carrying unix **epoch milliseconds**, and a replay window (ms → whole
  seconds by integer division, shared symmetric tolerance). Requires the new
  `VerifyOptions::request_method` option alongside `request_url`, since this
  is the only scheme that signs the HTTP method. Backed by an official test
  vector from HubSpot's webhook docs (the worked example reproduces the
  published `base64(HMAC-SHA256(...))` byte-for-byte).
- Coinbase (CDP) webhook provider — HMAC-SHA256 over `{t}.{raw_body}`,
  hex-encoded, `v0` scheme in the combined `X-Hook0-Signature` header
  (`t=`/`v0=` fields, `h=`/`v1=` header-binding fields tolerated but not
  interpreted) with timestamp tolerance. Follows the documented construction
  in Coinbase's Developer Platform webhook docs.
- Notion webhook provider — HMAC-SHA256 over the raw body, hex-encoded,
  `sha256=` prefix in the `X-Notion-Signature` header, keyed by the
  subscription's `verification_token`. Backed by an official test vector from
  Notion's docs (the worked-example token/body reproduce the documented
  sample signature byte-for-byte).
- Paddle webhook provider — HMAC-SHA256 over `{ts}:{raw_body}`, hex-encoded,
  combined `Paddle-Signature` header (`ts=`/`h1=` list, rotation-safe) with
  timestamp tolerance. Backed by Paddle's official Go SDK test vector and
  docs.
- `From<&str>`, `From<String>`, and `From<&String>` for [`Secret`](crate::Secret),
  so signing material can be built with the idiomatic `.into()`/`From`
  conversion as well as the explicit `Secret::new` constructor.
- `Provider` now implements `FromStr` (case-insensitive, canonical display
  names) for config-driven provider selection, with `ProviderParseError`.
- Cloudflare (Stream) webhook provider — HMAC-SHA256 over `time.body`,
  hex-encoded, combined `Webhook-Signature` header with timestamp tolerance.
- Xero webhook provider — HMAC-SHA256, base64, `x-xero-signature`.
- Dudect-style constant-time assertion for the core comparison path
  (spec §5.7). Runs as an informational, non-blocking CI job in release
  mode.
- Optional `max_body_size` on Tower `VerifyLayer` and Actix
  `WebhookConfig` for DoS hardening.
- Fuzz target covering Discord's Ed25519 signature-decode path
  (spec §5.6).
- The shared fuzz target (`fuzz/fuzz_targets/parse_and_verify.rs`) now also
  drives the cross-secret rotation path
  [`verify_any`](crate::verify_any) (spec §5.6): per-provider invocation with
  an empty secret slice (immediate `SignatureMismatch`), a garbage-then-
  well-formed slice (error aggregation must keep trying past `InvalidSecret`
  and reach the well-formed key), and an all-garbage slice (aggregation
  across every unusable key). The multi-secret loop gets the same "no panic,
  no timeout" guarantee the single-secret `verify` path already had.
- `CustomScheme::new()` convenience constructor plus the
  `with_timestamp_header` / `with_prefix` builders, so declarative schemes
  can be configured without a struct literal (spec §2.2).
- docs.rs now annotates feature-gated items (the `paypal`/`sendgrid`
  providers and the `tower`/`actix`/`http` adapters) with the crate feature
  they require, via `doc_auto_cfg` + the `docsrs` rustdoc cfg. Local/stable
  builds are unaffected (the cfg is set only on docs.rs).
- [`Provider`](crate::Provider) `FromStr` now also accepts the
  space-separated human-readable spellings used in the docs for the two
  providers whose `Display` name runs words together: `"lemon squeezy"` and
  `"standard webhooks"` (both case-insensitive, like every name). These match
  the product names operators see in `spec.md`/`README.md`, so a
  config-driven `"Lemon Squeezy".parse::<Provider>()` no longer fails.
- **New provider: CircleCI outbound webhooks** (`Provider::CircleCi`):
  HMAC-SHA256 over the raw request body, **hex**-encoded, delivered in the
  `circleci-signature` header as a comma-separated list of **versioned**
  signatures (`v1=<hex>[,v2=...][,v3=...]`). The signing key is the webhook's
  configured secret token, used verbatim as its UTF-8 bytes. The docs name
  `v1` as the latest (and only) signature version and direct integrators to
  check only the latest signature type to prevent downgrade attacks, so this
  provider verifies the `v1` element only and discards unknown versions and
  non-versioned elements for forward compatibility; a duplicate `v1` is
  rejected as ambiguous (`spec.md` §4.4) rather than last-wins like the
  reference Python verifier's dict literal. No timestamp is signed, so the
  shared `max_age` replay window has no effect (the docs recommend
  application-level deduplication on the payload `id`). Source:
  <https://circleci.com/docs/guides/integration/outbound-webhooks>
  ("Validate outbound webhooks"). The test vectors are the byte-exact
  body/secret/signature pairs CircleCI publishes in that section (the 200 and
  non-200 examples plus the extra pairs its `True`/`False` walkthrough signs),
  all cross-checked with OpenSSL; the boundary vectors are locally constructed
  over the same documented recipe. `Provider::from_str` also accepts
  `"circleci"` (plus the `"circle ci"` and `"circle-ci"` spellings).

- **New provider: Nylas** (`Provider::Nylas`): **hex** HMAC-SHA256 over the
  exact request body, keyed by the endpoint's `webhook_secret` (generated
  automatically after the endpoint passes Nylas's `challenge` handshake) as
  its UTF-8 bytes and delivered in the `x-nylas-signature` header — a bare
  lowercase hex digest, no prefix and no timestamp (the same bare-hex shape as
  LaunchDarkly, Dropbox, Razorpay, and Lemon Squeezy). Nylas's docs state the
  header arrives as either `x-nylas-signature` or `X-Nylas-Signature`, and
  header lookup is case-insensitive so both spellings work. The docs stress
  the signature is for "the exact content of the request body", so the crate
  hashes `raw_body` verbatim. With `compressed_delivery` enabled Nylas
  gzip-compresses the payload and signs the *compressed* bytes — callers pass
  the raw wire bytes straight through and verify before decompressing. No
  timestamp is signed, so `max_age` has no effect. Nylas documents the scheme
  and ships reference verification code plus a CLI `nylas webhook verify`
  oracle, but publishes no byte-exact example signature (the secret is
  endpoint-specific), so the vectors are locally constructed over exactly the
  documented recipe — the primary vector's body mirrors the shape of Nylas's
  documented `message.created` notification, including the always-included
  `id`/`grant_id`/`application_id` fields — cross-checked with OpenSSL and
  Python's `hmac`. Source:
  <https://developer.nylas.com/docs/v3/notifications/> ("Secure a webhook")
  and
  <https://developer.nylas.com/docs/cookbook/use-cases/build/verify-webhook-signatures/>.

- **New provider: Tally** (`Provider::Tally`): base64 HMAC-SHA256 over the
  exact request body, keyed by the per-webhook signing secret as its UTF-8
  bytes and delivered in the `Tally-Signature` header — a bare base64 digest
  (standard alphabet with padding), no `sha256=` prefix and no timestamp (the
  same shape as Shopify, Xero, and WooCommerce). The signing secret is
  optional: when none is configured, Tally sends unsigned requests, so this
  variant only verifies the signed case (an absent header fails closed with
  `MissingHeader`). Tally's official example hashes `JSON.stringify(payload)`
  after the body has already been parsed, a re-serialization round-trip that
  reproduces the wire bytes only when the parser preserves key order and
  whitespace; the crate hashes `raw_body` verbatim (spec §4), which is the
  signer's actual wire bytes. No timestamp is signed, so `max_age` has no
  effect; Tally retries failed deliveries on a back-off schedule and
  recommends deduplicating on the payload's `eventId`. Tally's docs describe
  the construction and publish an example event but no byte-exact signature
  (the signing secret is endpoint-specific and shown only once), so the
  vectors are locally constructed over exactly the documented recipe — the
  primary vector's body mirrors Tally's published example event — cross-checked
  with OpenSSL and Python's `hmac`. Source:
  <https://tally.so/help/webhooks> ("Add a signing secret"). `Provider::from_str`
  also accepts `"tally"`.

### Changed

- **Docs: clippy gate documented with `--all-targets`** — `spec.md` §6 and
  `AGENTS.md` (§4 workflow, §6 PR checklist) now document the clippy run the
  CI gate actually enforces (`cargo clippy --all-features --all-targets -- -D
  warnings`, PR #124). The spec previously listed the pre-`--all-targets`
  command, so a contributor following it locally would lint only lib+bins and
  let test-only drift through the exact gate that already shipped (#124).
  Documentation-only change; no verification behavior touched.
- **Lint: `missing_debug_implementations`** — all public types are now
  required to implement `Debug`, enforced by `#![deny(missing_debug_implementations)]`
  (mirrors the existing `#![deny(missing_docs)]` guard). Every public type
  already has a deliberately-redacted `Debug` impl (spec §4.3: `Secret`,
  `VerifyOptions`, `VerifyingKeyMaterial`, and `WebhookConfig` never surface
  secret material, raw bodies, or request URLs), so this is a zero-behavior
  hardening lint that prevents a new public type from shipping without a
  safe-to-log `Debug` impl — the same "guard future API surface" philosophy as
  the `missing_docs` deny that this entry mirrors.
- **Docs: GitLab discoverability** — GitLab's webhook "signing token" (GitLab
  19.0+) implements the Standard Webhooks specification, so
  `Provider::StandardWebhooks` verifies it with no new code. Documented in the
  README provider table, `spec.md` §3, and the module docs. Source:
  <https://docs.gitlab.com/user/project/integrations/webhooks>.
- **Klaviyo header constants are now public** —
  [`klaviyo::SIGNATURE_HEADER`](crate::klaviyo::SIGNATURE_HEADER),
  [`klaviyo::TIMESTAMP_HEADER`](crate::klaviyo::TIMESTAMP_HEADER),
  and the new
  [`klaviyo::WEBHOOK_ID_HEADER`](crate::klaviyo::WEBHOOK_ID_HEADER)
  are exported so callers performing Klaviyo's delegated
  `Klaviyo-Webhook-Id` ↔ `meta.klaviyo_webhook_id` pair check after a
  successful `verify()` can reference the actual header spellings instead of
  hardcoding them. The module docs previously directed callers to "the
  constants in this module" that were not part of the public API and carried
  no constant for the webhook-id header at all; the docs now point at the real
  items (also fixing a non-resolving intra-doc link).
- The crate-level `missing_docs` lint is `deny` instead of `warn`: an
  undocumented public item is now a hard compile error in every configuration
  (stable/MSRV/beta, clippy, and the `no_std` feature matrix) instead of a
  warning the contributor gates never promoted to failure. Docs on every
  existing public item already satisfy the bar; this only guards future API
  surface against silent doc drift.
- [`Provider`](crate::Provider) `Display` for the `Custom` variant now
  renders the full declarative scheme configuration (signature header, hash
  algorithm, encoding, and any configured prefix/timestamp header) instead
  of only the signature header name. Two custom schemes sharing a header
  name but differing in encoding or hash previously logged identically;
  operators can now tell them apart. The `signed_string` closure has no
  reliable textual form and is intentionally not rendered.
- `VerifyError::TimestampOutOfTolerance` `Display` no longer misdescribes
  `skew` as the excess *beyond* the `max_age` window. The field is the
  signed timestamp's total distance from "now" (`|now - timestamp|`,
  `src/core/replay.rs` `check_replay`), so a 600s distance over a 300s
  window previously read "600s outside the allowed 300s window" even though
  the excess is only 300s. The message now reads "600s from now exceeds the
  allowed 300s window", matching the documented field semantics (the doc
  fix in PR #138 aligned the field docs; this aligns the operator-facing
  message). Message-text only — the `skew`/`max_age` values printed, the
  failure condition, and every other `Display` variant are unchanged.

### Fixed

- **Contentful: full URLs without an explicit path preserve query strings.** A
  URL such as `https://example.com?source=webhook` now canonicalizes its request
  path as `/?source%3Dwebhook` instead of dropping the query, matching
  Contentful's documented path/query split and query encoding.
- **Contentful: bare request paths containing `://` are preserved.** A
  `VerifyOptions::request_url` value beginning with `/` is now treated as the
  bare path documented by Contentful instead of being truncated at an embedded
  scheme delimiter. Full-URL normalization is unchanged.
- **Docs: the built-in SHA-1 scheme enumerations now include Mailchimp
  Transactional.** Three places undercounted the built-in HMAC-SHA1 providers
  (the actual set is Vercel, Twilio, Intercom, Expo EAS, and Mailchimp
  Transactional — the README's provider table correctly lists all five): the
  `spec.md` §3 Vercel row claimed "Vercel, Twilio, Intercom, and Expo (EAS)
  are the built-in providers' four HMAC-SHA1 schemes" without Mandrill, the
  Vercel provider module docs named only Twilio and Intercom, and the
  `Provider::Vercel` doc comment (`src/providers/mod.rs`) omitted Mandrill.
  All three now enumerate the full five and keep the true sub-claim that
  Vercel is the only bare-hex raw-body SHA-1 scheme. Doc-only change;
  verification behavior is untouched.
- **Tailscale: non-canonical `t=` timestamps are now rejected.** The signed
  string reuses the raw `t` substring, and Tailscale's official verifier
  (`docs/webhooks/example.go`) signs the parsed integer re-formatted
  canonically (`fmt.Append(nil, timestamp.Unix())`). The shared timestamp
  parser accepts any pure-digit spelling, so a leading-zero value
  (`t=01663781880`) previously verified against a signed string the reference
  verifier can never produce — a silent divergence from the cited source.
  `t` values that are not in canonical decimal form (leading zeros, including
  `t=00`; a lone `t=0` remains valid) now fail closed as `MalformedHeader`,
  making the crate's signed string byte-identical to the official verifier
  for every accepted delivery. Tailscale only emits canonical values, so no
  legitimate delivery is affected. (`spec.md` §3 Tailscale row updated and the
  module-doc byte-identical claim is now actually true; same class as the
  Ripple verbatim-agreement gate.)

- **Fuzz seed-corpus doc comment now enumerates the Tailscale seed.** The
  `parse_and_verify` target's seed list
  (`fuzz/fuzz_targets/parse_and_verify.rs`) documented every committed corpus
  seed, but the `tailscale-t-v1-delivery` seed shipped with the Tailscale
  provider (#140) was never added to the enumeration — the comment claimed to
  cover the corpus yet listed 55 of its 56 files. The entry is now documented
  with the same rationale style as the rest (same drift class as the missing
  DocuSign/Paystack and LINE seeds fixed in #91/#101 and the Box/Vercel seeds
  fixed later). Comment-only; no behavior, seed bytes, or crate code affected.
- **`Provider::StandardWebhooks` `Display` now spells the brand the way the
  spec's own corpus does.** The enum variant's `Display` impl wrote
  `"StandardWebhooks"`, the only place in the crate that deviates from the
  official `Standard Webhooks` spelling used everywhere else (the enum doc
  comment, `spec.md` §3, README, `lib.rs`, the provider module docs, and the
  specification itself — the official repo calls it "Standard Webhooks",
  <https://github.com/standard-webhooks/standard-webhooks>). Following the
  Lemon Squeezy- and LINE-formatting precedents, the `Display` string now
  matches the brand, so callers doing an exact string compare on
  `provider.to_string()` (log filtering, config echo, tests) no longer get a
  false negative against `"Standard Webhooks"`. `FromStr` already matches
  case-insensitively and accepts the space-separated form, so round-trips and
  all existing parse tests are unaffected.
- **`Provider::LemonSqueezy` `Display` now spells the brand the way Lemon
  Squeezy does.** The enum variant's `Display` impl wrote `"LemonSqueezy"`,
  the only place in the crate that deviates from the official `Lemon Squeezy`
  spelling used everywhere else (the enum doc comment, `spec.md` §3, README,
  `lib.rs`, and the module docs). Following the LINE- and CircleCI-formatting
  precedents, the `Display` string now matches the brand, so callers doing an
  exact string compare on `provider.to_string()` (log filtering, config echo,
  tests) no longer get a false negative against `"Lemon Squeezy"`. `FromStr`
  already matches case-insensitively and accepts the space-separated form, so
  round-trips and all existing parse tests are unaffected.
- **`Provider::Line` `Display` now spells the brand the way LINE does.** The
  enum variant's `Display` impl wrote `"Line"`, the only place in the crate
  that deviates from the official `LINE` capitalization used everywhere else
  (the enum doc comment, `spec.md` §3, README, `lib.rs`, and the module
  docs). Following the CircleCI-capitalization precedent, the `Display` string
  now matches the brand, so callers doing an exact string compare on
  `provider.to_string()` (log filtering, config echo, tests) no longer get a
  false negative against `"LINE"`. `FromStr` already matches case-
  insensitively, so round-trips and all existing parse tests are unaffected.
- **Docs: a broken intra-doc link in the `Provider` `FromStr` parse-notes.**
  `ProviderParseError`'s implementation notes wrote
  `` `"lemon squeezy"`/`"lemon-squeezy"` ↔ [`Provider::LemonSqueezy`, `` —
  an opening `[` with no matching `]` — so docs.rs rendered the literal text
  `[ Provider::LemonSqueezy ,` instead of a link to the enum variant (the
  rest of the list, `StandardWebhooks`/`HubSpot`, linked normally). Unbalanced
  brackets do not trip `RUSTDOCFLAGS="-D warnings"`, so the `doc` CI job
  could not catch it. Doc-only change; verification behavior is untouched.
- **LINE: the signature-header constant and spec now spell the header the way
  LINE's docs do.** LINE's official "Verify webhook signature" docs send the
  digest in a lowercase `x-line-signature` header, but the crate's
  `SIGNATURE_HEADER` constant (surfaced in `VerifyError::MissingHeader` /
  `MalformedHeader` messages and the tower/actix duplicate-scan) used the
  title-cased `X-Line-Signature`. Following the Square precedent, the constant
  and the `spec.md` §3 LINE row now match the provider's spelling (lookup is
  ASCII case-insensitive, so this only changes operator-facing output, not
  verification behavior).
- **Crate docs: the Square provider row omitted its header name.** The
  supported-providers table in `src/lib.rs` and the `Provider::Square` doc
  comment described the scheme without naming `x-square-hmacsha256-signature`
  (the README and `spec.md` already named it), so a docs.rs reader had no way
  to learn the header to extract without cross-referencing. Doc-only change.
- **Spec: Contentful's self-describing signed-header list is documented as
  outside the adapters' duplicate-ambiguity scan.** The `spec.md` §4.4 rule
  claimed built-in providers' schemes are fully ambiguity-scanned, but
  Contentful's `x-contentful-signed-headers` list names additional signed
  headers at delivery time that cannot be known statically, so the tower/actix
  scan covers only the three fixed headers. The carve-out (identical to the
  one already documented for `CustomScheme`'s closure-read headers) is now
  stated in `spec.md` §4.4 and the Contentful row, and in the provider module
  docs. Doc-only change; the adapter scan was always correct — verification
  reads these headers first-match, matching handlers' `.get()`.
- **`ProviderParseError` message now names the rebrand/signer aliases
  `FromStr` accepts.** `"mailchimp"` (→ Mandrill) and `"svix"`/`"resend"`
  (→ StandardWebhooks) were parseable but absent from the error message that
  is meant to guide operators back to a parseable spelling, so a rejected
  alias-typed spelling was not echoed back. The message's trailing note now
  lists all three aliases (alongside the existing canonical and
  multi-word/hyphenated spellings), and the display guard test pins them so
  message/`FromStr` drift fails CI.
- **Spec: `Provider` enum sketch in §2 missed the Fintoc, Ripple, and X
  variants.** The Fintoc (#110), Ripple (#111), and X (formerly Twitter,
  #109) providers all shipped with their `spec.md` §3 rows and CHANGELOG
  entries but were never added to the §2 `pub enum Provider` code sketch, so
  the normative enum drifted from the shipped declaration order (the three
  variants sat before/after `Razorpay`/`Vercel` in the code but were absent
  from the spec). The sketch now lists all 49 variants (48 named + `Custom`)
  in the same order as `src/providers/mod.rs`. Doc-only change; no behavior,
  headers, or verification semantics affected.
- **Agent docs: the provider count claim in `AGENTS.md` was stale (46 vs.
  49).** The intro paragraph lagged the three provider additions above;
  updated to match the crate's `Provider` enum and the README provider table.
  Repo-internal doc-only change, excluded from the crates.io tarball.
- **RFC 3339 leap second: a local `23:59:60` with a non-zero UTC offset is
  no longer silently normalized into a replayable instant.** The shared
  `parse_rfc3339_timestamp` parser (used by PayPal, Twitch, Zendesk, and Box)
  gated RFC 3339's second-`60` leap-second value on the *local* clock
  position only, so a value like `2024-05-16T23:59:60+02:00` passed the gate
  but normalized to UTC `22:00:00` — an instant where no leap second exists.
  A leap second is only ever held at UTC `23:59:60`, so the parser now
  requires the offset-normalized instant to sit on that UTC day boundary and
  rejects the shifted spellings fail-closed (`23:59:60+02:00`,
  `23:59:60-05:00`); `23:59:60Z`/`23:59:60+00:00` still parse to the same
  instant they always did. Impact on real deliveries is nil — the four
  consumers HMAC-cover the timestamp and providers emit `Z`-suffixed values
  — but the parser is now stricter than before, matching the crate's
  fail-closed stance on timestamp shapes providers never emit.
- **Fuzz target: Ripple was missing from the `IMPLEMENTED` coverage list.**
  The Ripple provider (#111) added a well-formed-shaped `attempt` but was
  never added to the `parse_and_verify` target's `IMPLEMENTED` array, so its
  header parser and combined `t=...,v1=...` parser never received arbitrary
  fuzz bytes and never ran through the `verify_any` rotation loop —
  `spec.md` §5.6 requires every provider's parsing path in the shared target.
  Adding `Provider::Ripple` to `IMPLEMENTED` restores both; the target
  rebuilds and runs clean.
- **VerifyOptions docs: `request_url`'s and `form_params`'s provider lists
  omitted Mailchimp Transactional (Mandrill).** The `request_url` field doc
  enumerated "Square, Twilio, HubSpot" and `form_params` only "Twilio", but
  Mandrill's scheme is URL-scoped and signs the sorted form fields exactly
  like Twilio (`spec.md` §3, Mandrill row) — the same list the
  `with_form_params` builder doc already names ("currently Twilio and
  Mandrill"). The field docs now list all four URL-scoped providers and both
  form-field-signing providers, matching `spec.md` §2's field sketch.
  Doc-only change; no behavior, headers, or verification semantics affected.
- **Fuzz seed-corpus doc comment now enumerates the Box and Vercel seeds.** The
  `parse_and_verify` target's seed list (`fuzz/fuzz_targets/parse_and_verify.rs`)
  documented every committed corpus seed, but the `box-two-signature-delivery`
  and `vercel-hex-signature` seeds shipped with the Box (#97) and Vercel (#92)
  providers were never added to the enumeration — the comment claimed to cover
  the corpus yet listed 43 of its 45 files. Both entries are now documented
  with the same rationale style as the rest (same drift class as the missing
  DocuSign/Paystack and LINE seeds fixed in #91/#101). Comment-only; no
  behavior, seed bytes, or crate code affected.
- **Docs: Twilio rows now name the base64 encoding, and Vercel's SHA-1
  "only" claim is scoped to the built-in providers.** The crate-level and
  README provider tables described Twilio's scheme only as "HMAC-SHA1 over
  URL + sorted form params", omitting that its digest is **base64** — the
  only base64-HMAC among the built-in providers — and the lib.rs row omitted
  the `X-Twilio-Signature` header name; both rows now state the encoding and
  header. Separately, the Vercel variant/Provider and module docs called
  Vercel "the crate's only bare-hex raw-body SHA-1 scheme", which only holds
  for the *built-in* providers: a `CustomScheme` configured with `HashAlg::Sha1`,
  `Encoding::Hex`, no prefix, and the identity signed-string reproduces the
  same bare-hex shape. The claim is now scoped to the built-in providers,
  matching `spec.md` §3's phrasing, and notes that `Custom` can express the
  same scheme. Doc-only changes; no behavior or verification semantics.
- **`ParseRFC3339Timestamp` now accepts lowercase `t`/`z` separators.** The
  shared RFC 3339 parser (PayPal `PayPal-Transmission-Time`, Twitch
  `Twitch-Eventsub-Message-Timestamp`, Zendesk
  `X-Zendesk-Webhook-Signature-Timestamp`) previously rejected the lowercase
  `t`/`z` spellings that RFC 3339 §5.6 explicitly permits as the ISO 8601
  alternative to `T`/`Z`, producing a spurious `MalformedHeader` for an
  otherwise-valid timestamp. Parsing is still fail-closed and the raw
  timestamp bytes remain signature-covered, so accepting the RFC-legal
  lowercase spelling does not widen any replay or forgery surface.
- **Twitch: an empty `Twitch-Eventsub-Message-Id` now fails closed as
  `MalformedHeader`.** The message id stays opaque — no UUID/format grammar
  is imposed, and a garbage value is still signed verbatim and verifies only
  against a signature made over that exact value — but an empty value is
  never a legitimate Twitch delivery. It previously flowed into the signed
  string and surfaced as `SignatureMismatch`; it is now rejected as
  `MalformedHeader` ("header is empty"), matching the fail-closed treatment
  of Standard Webhooks' opaque `webhook-id` (`spec.md` §3, §4.4). Adds the
  §5.5 empty-value and garbage-value tests the provider was missing.
- The `parse_and_verify` fuzz target now drives constant-time-shape attempts
  for the five raw-body single-header providers that previously only ran with
  arbitrary fuzz-input headers — Dropbox, LemonSqueezy, Linear, Shopify, and
  Xero. Each gets a well-formed signature-header value (bare hex or bare
  base64 of the 32-byte gate) so arbitrary body bytes reach the 32-byte
  length gate and HMAC comparison instead of failing earlier on
  malformed/missing headers, matching the coverage Cloudflare/Notion/
  Typeform/Coinbase/Paddle/HubSpot already had (spec §5.6). The
  `IMPLEMENTED`-list comments claimed "a well-formed-shaped attempt below"
  for LemonSqueezy when none existed, and the other four said nothing where
  one now does; the comments now match the code.
- The `parse_and_verify` fuzz target's seed-corpus comment described Paddle's
  signed string as `{ts}.{body}` — the `ts`/`h1` entries are joined with a
  colon, Paddle's documented `hmac(secret, "{ts}:{body}")`. The comment now
  matches `src/providers/paddle.rs` and `spec.md` §3's Paddle row. Comment-only
  change; no behavior, seed bytes, or crate code affected.
- `cargo fuzz build` now also compiles the `paypal`-only feature combination
  (without `sendgrid`): the fuzz target imported `VerifyingKeyMaterial` under
  `#[cfg(feature = "sendgrid")]` alone, so the `not(feature = "sendgrid")`
  fallback arms the target ships for the paypal-only build failed with an
  unresolved import. The import is now gated on `any(sendgrid, paypal)`,
  matching the cfg blocks that use it.
- README `no_std` and security notes: multi-line inline code spans with stray
  two-space indentation rendered mangled — commands gained spurious spaces
  (e.g. `--target  wasm32-unknown-unknown`) and a parenthetical dangled
  mid-sentence. Each span now sits on a single line; the narrative flows as
  one paragraph. Content is unchanged.
- Removed the `probe_ci_write_test.yml` debris file left at the repository root
  by a CI permission-probe commit. It was tracked on `master`, not excluded from
  the package, and would have shipped verbatim in the crates.io tarball.
- Discord: a configured public key that decodes to 32 bytes but is not a valid
  Ed25519 compressed point now fails closed with
  [`VerifyError::InvalidSecret`](crate::VerifyError), matching the module's
  documented contract, instead of surfacing as
  [`VerifyError::SignatureMismatch`](crate::VerifyError). The two are distinct
  failure classes in the adapters: a bad key is operator misconfiguration
  (HTTP 500), while a signature mismatch is treated as a forged request (HTTP
  401). Verification outcome is unchanged — such keys could never have verified
  — only the error classification is corrected. Roughly half of random 32-byte
  values fail point decompression, so this catches a common class of
  copy-paste-corrupted Developer Portal keys.
- The `no_std + alloc` configuration is now behaviorally testable: the full test
  suite compiles and passes with `cargo test --no-default-features --features
  sendgrid,paypal` (tests run on the host, no wasm target needed). Test modules
  pick up the standard-prelude names they assume (`String`, `Vec`,
  `ToString`, `format!`, `vec!`) through a `no_std`-gated re-export in the
  shared test helpers — previously the `cfg(not(feature = "std"))` branches
  (the wall-clock fallback in `VerifyOptions::now()`, the
  `std::error::Error`-less `VerifyError`, and the `no_std` re-exports) were
  only build-checked for `wasm32`, so a behavioral regression in them would
  pass CI.
- The contributor gate now builds the docs with `RUSTDOCFLAGS="-D warnings"`
  (AGENTS.md §6), so a broken intra-doc link is caught at review time instead
  of silently degrading docs.rs output. (docs.rs itself builds with
  `-D warnings`; the `doc` CI job now enforces the same flag.)
- spec.md: corrected CI claims that outran the workflow wiring. The
  `-D warnings` doc build and the `no_std` behavioral test run were
  temporarily marked as local/pre-merge gates (issues #18/#22), and have
  since shipped in `.github/workflows/ci.yml` (see the Added section above).
  The §5.7 constant-time bullet no longer describes its already-shipped
  informational CI job as "tracked separately"; and the §7 PayPal ship date
  typo `(2026-10)` is fixed to `(2026-09)` (PayPal and SendGrid both shipped
  in the initial 2026-09 commit).
- `VerifyOptions::with_form_params` docs: the builder claimed "Order does not
  matter; fields are sorted into signing order during verification." That
  holds for distinct field names, but Twilio's scheme signs same-named fields
  in their received relative order (the sort is stable, `spec.md` §3, Twilio
  row), so passing duplicates reordered broke verification while the docs
  implied any order was safe. The docs now state the duplicate-names
  exception, matching the field documentation and the implementation.
- `CustomScheme` replay-protection caveat: the docs now state that the replay
  window only *binds* when the `timestamp_header` value is copied into the
  bytes `signed_string` returns. The check runs against the header alone, so
  a closure that signs the body only leaves the timestamp
  attacker-rewriteable — replaying a captured request with a freshened header
  still verifies, silently defeating the protection. A test pins both halves
  of the documented limitation (stale header rejected, freshened header
  accepted) so the caveat cannot silently drift from the behavior; the
  built-in timestamped providers are unaffected (their signed strings embed
  the timestamp by construction).
- `VerifyError::TimestampOutOfTolerance` `Display` no longer truncates the
  reported skew to whole seconds: a sub-second skew over a sub-second
  `max_age` window previously read e.g. `0s outside the allowed 100ms
  window`, which misdescribes the rejection. The skew now renders like the
  window does (`Duration`'s `Debug`), e.g. `150ms outside the allowed 100ms
  window` — the same second half of the sub-second-tolerance fix that
  already applied to `max_age`.
- The `no_std + alloc` guarantee now actually holds at the dependency level:
  `base64`, `hex`, and `subtle` were declared with default features, each of
  which turns on that crate's `std` feature (`extern crate std`) — invisible
  to the wasm32 CI gate, which ships std, so a stray `--no-default-features`
  build for a genuinely std-less target (bare-metal, no_std wasm) failed in
  the dependency tree. All three are now declared `default-features = false`
  (base64/hex keep [`alloc`]), matching every other dependency's
  no_std-first posture; the `--no-default-features` core and `sendgrid` build
  now compile for `riscv32imac-unknown-none-elf`.
- spec.md/README/Cargo.toml: the `paypal` feature is now documented as
  std-bounded in practice. The §3 PayPal row and the §7 implementation notes
  previously described the feature as `no_std`-compatible, but its
  certificate path pulls `der-parser` and `nom` (via `x509-parser`) with
  their default features, re-enabling `std` in `num-traits`/`num-bigint`/
  `memchr` — and Cargo's union feature-unification means a
  `default-features = false` edge on this crate's own dependency cannot
  revoke those. A `--no-default-features --features sendgrid,paypal` build
  for a genuinely std-less target fails inside `num-traits` with
  `can't find crate for std` (invisible to the wasm32 CI gate, which ships
  std). The `no_std + alloc` scope is core + `sendgrid`, unchanged; the
  host-based no_std test in §6 still passes because host builds have std.
  See issue #23.
- Square: the signature-header constant and README table used the
  title-cased `X-Square-HmacSha256-Signature`, but Square's own docs, the
  crate's `spec.md` §3, and the provider module docs all spell the header
  `x-square-hmacsha256-signature`. The constant and README now match the
  provider's spelling (lookup is ASCII case-insensitive, so this only
  changes the header name surfaced in `VerifyError` messages on the
  adapter duplicate-scan, aligning operator-facing output with Square's
  documentation).
- Paddle malformed-header test battery: the `ts=not-a-number` case used a
  comma (`ts=not-a-number,h1=…`) where `Paddle-Signature` elements are
  `;`-separated. `parse_header` split the lump into a single `ts` element,
  folding the `h1=` field into the timestamp value, so the test passed
  without ever parsing the signature field it claimed to cover. The header
  now uses the documented `;` separator and genuinely exercises a
  well-formed `h1=` signature coexisting with an unparsable timestamp.
- `CustomScheme` docs: the ambiguity-check caveat referenced
  `signature_header_names` (a crate-private helper, not a public item) and the
  two scheme header names via broken intra-doc links, producing rustdoc
  warnings on every `cargo doc` build (including docs.rs). The links now
  resolve to the `CustomScheme` fields, and docs.rs builds the docs with
  `-D warnings` so broken links cannot regress silently on docs.rs.
- Crate-level docs: the Paddle row in the supported-providers table misstated
  the signed-string construction as `ts.body`; it is `{timestamp}:{raw_body}`
  (literal colon), matching `spec.md` §3 and the implementation.
- Crate-level docs and README: the SendGrid row described the signed message
  as `timestamp.body` (implying a dot separator); it is the raw timestamp
  header immediately concatenated with the raw body, no separator,
  matching `spec.md` §3 and the implementation.
- GitHub: the `sha256=` prefix in `X-Hub-Signature-256` is now matched
  case-sensitively, matching GitHub's reference implementations
  (octokit/Ruby). Uppercase/mixed-case prefixes (`SHA256=…`, `Sha256=…`)
  fail closed with `MalformedHeader` instead of being leniently accepted,
  bringing the code into conformance with the literal `sha256=` prefix
  already documented in the spec.
- Standard Webhooks: empty `webhook-id` header now fails closed with
  `MalformedHeader` instead of silently building a wrong signed string
  that masquerades as `SignatureMismatch` (spec §5.5 consistency).
- `verify_any` doc example now actually runs and verifies (it previously
  showed empty headers/body under `no_run`, which would have failed with
  `MissingHeader` if executed).
- PayPal timestamp parsing: strict RFC 3339 leap-second position
  (spec §3.8).
- Doc consistency nits for Zoom and SendGrid provider entries.
- Broken `HashMap` doc link in `HeaderMap` docs under `no_std` (the link
  resolved only with the `std` feature enabled).
- `verify_any` semantics for asymmetric providers clarified in docs.
- README example code fixed (undefined variables).
- Replay protection now honors sub-second `max_age` tolerances exactly:
  `check_replay` previously compared whole-second skew against
  `max_age.as_secs()`, silently flooring a `Duration::from_millis(500)`
  window to 0s (accepting any timestamp) and a `3500ms` window to 3s.
  `TimestampOutOfTolerance` `Display` likewise no longer truncates the
  window to whole seconds in operator-facing messages.
- `no_std` CI spec drift corrected.
- `verify_any` docs corrected: `TimestampOutOfTolerance` is reachable only
  *after* a signature verifies (every timestamped provider checks the
  replay window after the signature comparison), so a stale request with no
  matching key reports `SignatureMismatch`, not `TimestampOutOfTolerance`.
  A regression test pins the behavior (issue #12).
- `tower` and `actix` features now imply `std`: combining either with
  `default-features = false` previously broke with raw `cannot find crate
  std` errors, even though the `no_std + alloc` guarantee is scoped to the
  core path (`spec.md` §7). The combos now compile (they reintroduce `std`).
- Adapter docs (tower `VerifyLayer`/actix `WebhookConfig` module docs,
  `with_max_body_size` rustdoc, README): the `max_body_size` limit was
  described as preventing the server from *buffering* an arbitrarily large
  payload. Both adapters fully buffer the body before the size check
  (verification requires the exact wire bytes), so the claim overstated the
  guarantee. The docs now say the limit bounds the signature-verification
  CPU work only — a `413` still fires before any signature work, but memory
  buffering of an oversized body is not prevented.
- Crate-level doc example: the GitHub delivery snippet is no longer `no_run`.
  It executes as a doc-test, so a regression in GitHub's verification fails
  `cargo test` through its doctests (mirroring the earlier `verify_any` doc
  example conversion).
- `Provider` enum reordered to match the lib.rs doc table.
- Contributor gate (AGENTS.md): the PR definition-of-done now includes
  `RUSTDOCFLAGS="-D warnings" cargo doc --all-features --no-deps`, so broken
  intra-doc links (rustdoc warnings) are caught pre-merge. docs.rs builds with
  `-D warnings` by default; the `doc` CI job now enforces the same flag, so
  the local gate and CI fail together.
- README "Releasing" instructions now tag the release `v0.1.0` (matching
  `Cargo.toml`'s version) instead of the template's `v0.2.0`.
- Cloudflare and Coinbase combined-header fields (`time`/`sig1` and `t`/`v0`)
  are now rejected when repeated instead of first-wins: ambiguous signing
  material fails closed (`spec.md` §4.4), matching the existing Stripe and
  Paddle behavior.
- Docs: the HubSpot URI-decoding caveat is now surfaced where operators
  configure it. `VerifyOptions::request_url` and the README provider table
  state that HubSpot URL-decodes certain characters (`spec.md` §3 lists them)
  when computing its signature, so the URI must be passed in the same decoded
  form HubSpot signed. Previously only the provider module docs and the spec
  carried the caveat, and a proxied percent-encoded URI failed with an opaque
  `SignatureMismatch`.
- The `cargo audit` CI job was failing on three RustSec advisories that cannot
  be removed from the lockfile today (issue #41): `rsa` 0.9.10 (RUSTSEC-2023-0071,
  Marvin private-key timing attack — upstream has no patched release, and this
  crate only ever runs `RsaPublicKey::verify`, never a private-key operation),
  `time` 0.3.45 (RUSTSEC-2026-0009, fix >=0.3.47 requires Rust 1.88 > MSRV
  1.85; actix adapter stack only), and `h2` 0.3.27 (RUSTSEC-2026-0258, fix is
  the >=0.4.16 major bump for which actix-http has no 0.3-line patch; actix
  adapter stack only). The three are now documented and individually justified
  in `.cargo/audit.toml`, and the job is **blocking** again — a new advisory
  will fail CI and be triaged, while the three accepted ones carry an audit
  trail and re-evaluation triggers instead of failing every run.
- The `fmt` CI gate now also checks the `fuzz/` crate: it is a separate
  package (not a workspace member), so the root `cargo fmt --all -- --check`
  never saw it and the fuzz target had silently drifted out of rustfmt
  style. The job now runs `cargo fmt --manifest-path fuzz/Cargo.toml -- --check`
  after the root check (rustfmt needs no nightly/libfuzzer build), and the
  target is reformatted. No behavior, seed bytes, or crate code affected.
- `secret-leak-grep` CI job comment now matches the actual gate: it falsely
  implied a fixture allowlist exists ("extend the allowlist here
  deliberately") where spec.md §6 states there is *no* allowlist and the grep
  covers all of `src/`, including `#[cfg(test)]` test modules. Comment-only
  change; the grep pattern and the jobs it gates are unchanged.
- `.cargo/audit.toml`: fixed "Revist" → "Revisit" in the `time` advisory's
  re-evaluation-trigger note. Comment-only change.
- **Fuzz target: PayPal was missing from the `IMPLEMENTED` coverage list.**
  The PayPal provider ships a dedicated well-formed-shaped `attempt` (with a
  constant test certificate) but was never added to the `parse_and_verify`
  target's `IMPLEMENTED` array — the same drift class as Ripple (#112) — so
  its five required-header lookups, empty-header checks, and fail-closed
  `MissingContext` paths never received arbitrary fuzz bytes and never ran
  through the `verify_any` rotation loop. `spec.md` §5.6 requires every
  provider's parsing path in the shared target; adding `Provider::PayPal` to
  `IMPLEMENTED` restores both. The target rebuilds and runs clean.
- **StandardWebhooks: the Openlayer vector tests now follow the module's
  `official_*` naming convention.** Every other brand-alias vector in
  `src/providers/standard_webhooks.rs` — `official_brex_*`,
  `official_lithic_*`, `official_prescience_*`, `official_helcim_*`,
  `official_360learning_*`, `official_natural_*`, `official_origami_*`,
  `official_parallel_*`, and `official_celitech_*`, whether backed by a
  publisher-provided example or by the §5.1 recipe fallback — is named
  `official_<brand>_vector_<purpose>`. The Openlayer tests added with the
  alias (PR #204) dropped the prefix (`openlayer_vector_verifies`/`…_negative_flip_fails`/`…_tampered_body_fails`),
  making them the only vectors in the module that read differently from their
  siblings despite being built the same way. They are renamed to
  `official_openlayer_*`, keeping the module's test names greppable by brand
  and honest about the §5.1 recipe provenance the doc comments already state.
  Test-name-only change; no verification behavior, fixture values, or vector
  signatures are touched.

## [0.1.0] - Unreleased

Initial release (in progress). See [Unreleased](#unreleased) for the
full feature set targeting v0.1.
