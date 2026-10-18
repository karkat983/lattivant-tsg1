# Auth configuration (Task 2)

The reference target is the Rust `authz-target` (`authz-fuzzer/scanner/crates/authz-target`),
which the live lab already uses. It already seeds two tenants with distinct users, so it
needed **no identity changes**: `tok-alpha-admin` and `tok-alpha-viewer` (tenant alpha) and
`tok-bravo-admin` (tenant bravo). It has no `charlie` tenant and no editor role.
`token_check.txt` is the raw check: each user reads its own tenant's order (200), gets 403
across tenants, and no token gets 401.

| File | Used by | Users (user 1 = owner, user 2 = other identity) |
|---|---|---|
| `restler_tokens_alpha-bravo.sh` | RESTler `--token_refresh_command` | alpha-admin, bravo-admin |
| `restler_tokens_viewer-admin.sh` | RESTler, `admin-legit` mode only | alpha-viewer, alpha-admin |
| `wfc_alpha-bravo.yaml` | EvoMaster (`auth:` in its config) and Schemathesis (`[auth.wfc]`, both users as peers) | alpha-admin, bravo-admin |
| `wfc_viewer-admin.yaml` | same, `admin-legit` mode only | alpha-viewer, alpha-admin |

authz-fuzzer gets the same identities in its scan manifest (written by the driver).
All tokens are the target's synthetic, hard-coded lab tokens; none is a real credential.
