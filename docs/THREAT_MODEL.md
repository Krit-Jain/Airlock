# Threat model

Airlock is a defense against **prompt-injection hijacking**, not a general-purpose
security product. This document states what it does and does not protect against so the
claims stay honest.

## What Airlock defends against

- **Hijacking by construction.** The quarantined model can only emit closed enums,
  booleans, and sentence indices. There is no free-text output field, so attacker text
  cannot be copied back out by the model and later reach a sink, an MCP client, or a
  privileged-side prompt.
- **Cross-message poisoning.** Each message is processed in an isolated call with no
  history, so message A cannot poison the context used for message B.
- **Hidden and invisible content.** Deterministic sanitization strips and flags hidden
  HTML and invisible Unicode before any model sees a message.
- **Trust laundering.** The model cannot raise a sender's trust. Trust labels are computed
  by code from headers, domains, hidden content, and contacts.

## What Airlock does not defend against

- **Lying.** A message can still be misleading or a genuine business-email-compromise
  scam. The human sees the real quote and a trust label, but Airlock does not decide
  truth.
- **Enum steering.** An attacker who knows the schema can try to steer category,
  urgency, or request type. This is measured as the manipulation rate and mitigated with
  trust caps and (optionally) two-model disagreement. It is not claimed to be solved.
- **Side channels.** Timing, which messages exist, and metadata are out of scope.
- **Sender forgery beyond headers.** For email, trust uses the available authentication
  headers; for WhatsApp there is no authentication and the sender is unverifiable.

## Assumptions

- The local machine running Airlock is trusted.
- The quarantined model is a small open-weight model run locally through Ollama with
  structured-output sampling enabled.
- The local SQLite store and HTML brief are only readable by the machine owner.

## The manipulation-rate caveat

Hijack prevention and manipulation prevention are different. Airlock's hijack rate is
zero by construction. The manipulation rate measures how often an attack successfully
steers enum values, and it is reported separately before and after the trust cap.
