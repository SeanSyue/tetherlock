# Security, fixed defects and limits

## Status

Tetherlock is an MIT-licensed reference component extracted from a larger desktop system. There is no scheduled maintenance, response-time commitment or promised security release. The author may revisit it. Review and fix applicable defects before using it to protect real data; it is not independently security-certified.

This document describes version 0.1.0 including the follow-up fixes on 2026-09-26.

## Design boundary

The design uses Ed25519-signed tokens, explicit host-supplied trust, scope passwords checked through scrypt verifiers, and host-driven polling. Verifying machines need public keys; signing keys belong offline. Re-reading the token after a password prompt addresses a device-swap window; a password typed into a prompt that outlived a sign-out or loss of eligibility is discarded.

The host owns account eligibility, trust-directory permissions, UI teardown, file handles, polling and per-record policy. The library cannot constrain its own caller; a malicious host can bypass it. No application-level encryption of live workspace data is provided. The optional encrypted package utility is separate.

## Reviewed defects and fixes

AI-assisted review of earlier, unpublished snapshots found the defects below. The fixes have regression tests; this process is not an independent professional security audit.

| Area | What was wrong | Fix | Tests |
|---|---|---|---|
| Maintenance invalidation | An active session only checked that the token file still existed. A corrupted or replaced token left capabilities active. | Every use re-verifies the token (signature, trusted key, device, expiry) and requires the exact payload the session was opened with. | `test_maintenance.py`: `test_token_content_destroyed_ends_session`, `test_token_replaced_by_another_valid_token_ends_session`, `test_token_resigned_by_untrusted_key_ends_session` |
| Maintenance scope | A valid token of another scope could open a maintenance session. | Only `maintenance.v1` tokens are accepted; non-string capability entries are ignored. | `test_workspace_token_with_capabilities_cannot_open_maintenance`, `test_non_string_capabilities_are_ignored` |
| Sign-out during prompt | `lock_all()` while a password prompt was open did not stop the pending answer from unlocking afterwards. | `lock_all()` invalidates open prompts (a session generation counter); eligibility is checked again after the prompt; an area opened while `lock_all()` ran is closed again. | `test_monitor.py`: `test_sign_out_during_prompt_discards_the_password`, `test_user_switch_during_prompt_discards_the_password`, `test_losing_authorization_during_prompt_discards_the_password`, `test_lock_all_while_host_is_opening_closes_it_again` |
| Malformed token bytes | Invalid UTF-8, lone surrogates or deep nesting raised exceptions other than `AccessTokenError`; an unlocked area could stay open. | Token and manifest files are size-limited and every parse failure becomes `AccessTokenError`. The monitor locks an area whose check fails, even on an unexpected error, before passing the error on. | `test_access.py`: `test_hostile_token_bytes_raise_access_token_error`; `test_monitor.py`: `test_token_turned_into_garbage_locks_without_raising`, `test_unexpected_error_in_device_check_locks_before_raising` |
| Package resource cost | An unauthenticated package header could request unbounded scrypt cost. | Format, KDF, salt and nonce length, and upper bounds on N, r and p are checked before any key derivation; header and file sizes are capped before reading. Signed tokens get the same upper bounds. | `test_package.py`: `test_hostile_header_is_refused_before_key_derivation`, `test_package_size_limit_is_checked_before_reading`; `test_access.py`: `test_signed_but_unreasonable_scrypt_cost_is_refused_without_running_it` |
| Dependency range | `cryptography>=41` allowed releases with published advisories. | Raised to `cryptography>=50.0.1`, the version the suite was run with, which is at or above the fixed version of every cryptography advisory listed by OSV on 2026-09-25. Whether older advisories were reachable here was not assessed. | Suite run on Python 3.10.11 and 3.14.6 with cryptography 50.0.1 |

Relevant code: [`maintenance.py`](src/tetherlock/maintenance.py), [`monitor.py`](src/tetherlock/monitor.py), [`access.py`](src/tetherlock/access.py), [`package.py`](src/tetherlock/package.py).

The 2026-09-26 follow-up closes three additional failure paths:

- A scope teardown exception no longer skips remaining device revocations or the account-eligibility check. The first error is raised only after the revocations are attempted; no new unlock is started in that tick. The host must still actually close its resources: removing a library grant cannot repair a failed host callback.
- Package reads enforce `MAX_PACKAGE_BYTES + 1` at the read itself, rejecting an over-limit result even if the file grew after the initial size check. A complete oversized header is also tested before key derivation; that header guard already existed in the previous version.
- An exception from the maintenance clock clears the active session before propagating the exception, so a later successful clock call cannot revive the old session.

Four new regression cases fail against the previous version and pass after these fixes. The additional complete-header test passes on both versions, confirming an existing protection rather than claiming a new fix.

## Other deliberate limits

- No per-token revocation list. A lost device remains valid until expiry or key deprecation.
- Volume-serial binding does not prevent full-drive cloning; non-Windows identifiers are weaker.
- Removal is detected by polling, not instantaneous hardware events.
- Trust writable by an ordinary user lets that user choose trusted keys. Protect it outside the user's control.
- No defense against a stolen signing key and its password, administrator access, or same-user malware.
- Path checks are not an exclusive filesystem lock against another process changing paths during use. Host integration must address its environment.
- Plugin loading is not an untrusted-code sandbox.
- Package extraction reads up to 1 GiB plus one overflow-detection byte into memory and runs in-process with no time limit. Decryption and extraction need additional memory; the read cap is not a total process-memory budget.

Current tests and package checks are recorded in the [README](README.md). Passing tests show that the cases above now fail closed; they do not prove that no other defects exist. The release scan found no confirmed real credentials; that says nothing about secrets generated later by an adopter.

Do not publish real tokens, passwords, private keys or parent-system data in issues. No report-handling timetable is promised.
