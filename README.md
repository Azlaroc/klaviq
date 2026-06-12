# klaviq

> Resolve and inject secrets at runtime via `secret://` references.

**klaviq** fetches secrets from your vault on demand and hands them to your apps —
as environment variables, into a child process, or as files — **without writing
them to disk or caching them**. You reference a secret by a stable address:

```
secret://<vault>/<cred>
```

klaviq resolves that address against your vault at the moment you run, injects the
value, and forgets it. Think `op run`, but for a vault you host yourself.

### What klaviq is *not*

klaviq is **not a vault**. It does not store, encrypt, or manage your secrets —
your vault does. klaviq is a thin, stateless client: **no database, no server, no
API.** The only thing it keeps on disk is a single OS-encrypted blob holding the
credentials it needs to reach your vault. That's the whole security story:
*klaviq doesn't hold your secrets — your vault does.*

> **Backend:** klaviq talks to [Devolutions Hub](https://devolutions.net/) through
> the official `Devolutions.PowerShell` module. klaviq is an independent project,
> not affiliated with or endorsed by Devolutions.

---

## Quickstart

From nothing to a working `klaviq get` on a fresh box.

**On Devolutions Hub** (one-time)

1. Create a [Devolutions account](https://devolutions.net/hub/business/sign-up/) and a
   **Hub Business — Free** hub — *not* Hub Personal ([why](#2-install)).
2. In **Administration**: create a **Secrets vault**, then an **Application Identity**
   (enabled / no user-vaults / non-admin), then grant that identity **Privileged
   readers** on the vault. Copy the **ApplicationKey + ApplicationSecret** shown *once*.
   → [full steps](#3-authentication-bootstrap)
3. Collect just three things: the **ApplicationKey** + **ApplicationSecret** (from the
   App Identity page) and your **Hub URL**. *No vault GUID needed* — klaviq lets you
   pick the vault by name during bootstrap.

**On each machine that consumes secrets**

4. Install prerequisites: **PowerShell 7+**, the **`Devolutions.PowerShell`** module
   (needed by *every* klaviq command, not just bootstrap), and on Linux **`age`**.
   → [details](#2-install)
5. Put klaviq on your PATH (the `bin\` shim, or an alias). → [details](#2-install)
6. **Bootstrap:** `klaviq bootstrap -ManualPaste` — paste key + secret + url; klaviq
   then lists your vaults so you can pick a default by name (optional). Validates
   against Hub and writes the encrypted, machine-bound blob.
   → [details](#3-authentication-bootstrap)
7. **Verify:** `klaviq status` → expect `hub-reachable: true` with your vault listed.
8. **Use it:** `klaviq get secret://<vault>/<cred>`. → [the verbs](#4-usage--the-verbs)

That's production-ready. *(A multi-host fleet can optionally stage the App-Identity
values in a dedicated "bootstrap" vault for self-seeding; a single host just pastes
them in step 6.)*

---

## Index

1. [What it is](#1-what-it-is)
2. [Install](#2-install)
3. [Authentication (bootstrap)](#3-authentication-bootstrap)
4. [Usage — the verbs](#4-usage--the-verbs)
5. [Reference syntax](#5-reference-syntax)
6. [Deploy manifest](#6-deploy-manifest)
7. [Credential types](#7-credential-types)
8. [Exit codes](#8-exit-codes)
9. [Security model](#9-security-model)
10. [Troubleshooting](#10-troubleshooting)

---

## 1. What it is

A small cross-platform (Windows + Linux) CLI with five verbs — `get`, `run`,
`deploy`, `list`, `status`. You keep `secret://vault/cred` references in your
configs, env files, or compose manifests; klaviq resolves and injects them at
runtime so a plaintext secret never lands in a file or your shell history.

## 2. Install

> **Prerequisite — Devolutions Hub Business.** klaviq authenticates with a Hub
> **Application Identity**, which is a [Devolutions Hub **Business**](https://devolutions.net/password-hub/)
> feature. The free **[Hub Business Free](https://docs.devolutions.net/hub/getting-started/create-hub/devolutions-hub-business-free/)**
> edition is sufficient (no credit card required). **Devolutions Hub *Personal*
> will not work** — it has no Application Identities and no `Devolutions.PowerShell`
> integration, both of which klaviq depends on.

**Requirements**

- **PowerShell 7+** (`pwsh`) — cross-platform.
- The **`Devolutions.PowerShell`** module:
  `Install-Module Devolutions.PowerShell -Scope CurrentUser`
- **Linux only:** [`age`](https://github.com/FiloSottile/age) (e.g. `apt install age`) —
  used to encrypt the local auth blob.

**Put klaviq on your PATH**

- **Windows:** add the `bin\` directory to your PATH, then call `klaviq` (it shims
  to `klaviq.ps1`).
- **Linux / macOS:** alias it, e.g.
  `alias klaviq='pwsh -NoProfile -File /path/to/klaviq.ps1'`.

**Environment overrides** (optional)

| Variable | Overrides |
|---|---|
| `KLAVIQ_HUB_URL` | default Hub URL for bootstrap (so you're not asked each time) |
| `KLAVIQ_BLOB_PATH` | location of the encrypted auth blob |
| `KLAVIQ_KEY_PATH` | (Linux) the `age` identity key |
| `KLAVIQ_SECRET_DIR` | where `deploy` materializes secret files |

If unset, platform defaults are used (see [Authentication](#3-authentication-bootstrap)
and [Deploy](#6-deploy-manifest)).

## 3. Authentication (bootstrap)

klaviq authenticates to your vault with a Devolutions Hub **Application Identity**
(`applicationKey` + `applicationSecret` + Hub URL; the vault is optional). Set this up once.

### A. One-time Hub setup (vault + App Identity)

In the Hub portal, under **Administration**:

1. **Create a Secrets vault** — *Vaults* → **+** → *Secrets vault* → name it (e.g.
   `prod`). That **name** is all you need — klaviq references vaults by name, so you
   never have to dig out a GUID.
2. **Create an Application Identity** — *Application identities* → **+**:
   - **Is enabled:** on
   - **Can access user vaults:** off — no implicit access; you grant it explicitly
   - **Is administrator:** off — a consumer identity is never an admin
   - *(optional)* enable **IP restriction** for fixed-IP servers
   - On **Submit**, the portal reveals the **ApplicationKey** and
     **ApplicationSecret** *once* — copy both immediately. They cannot be
     recovered afterward, only regenerated.
3. **Grant the identity access to the vault** — *Vaults* → your vault →
   **Security** → *Edit* → add the identity (directly, or via a user group) to a
   role that can read secrets:
   - **Privileged readers** — read + reveal values; the minimum klaviq needs.
   - **Privileged operators** — also create/update entries (only if you want that).

   Save. The grant takes effect on klaviq's next call — no re-bootstrap needed to
   add or change vault access later.

You now have what klaviq needs: the **ApplicationKey**, the **ApplicationSecret**, and
your **Hub URL**. You don't need the vault's GUID — klaviq finds your vaults by name
(and offers to set a default during bootstrap).

> App Identities are created in the portal UI only — there is no cmdlet to mint
> them. See Devolutions' [Application identities](https://docs.devolutions.net/cloud/web-interface/administration/management/application-users/)
> docs for the authoritative walkthrough.

### B. Bootstrap klaviq

`klaviq bootstrap` captures key + secret + url (vault optional) into a local, **OS-encrypted** blob — DPAPI
(CurrentUser scope) at `%LOCALAPPDATA%\klaviq\auth.dat` on Windows, `age` (X25519)
at `~/.config/klaviq/auth.age` on Linux (identity key at `~/.config/klaviq/auth.key`,
`0400`). The blob is bound to the current user + machine. klaviq validates against
Hub before writing, and the secrets it later fetches are never persisted.

> **No RDM Desktop required.** The seed is just `{ key, secret, url, vaultId }` JSON —
> source it however your environment allows (paste, the Hub API, your CI pipeline).
> Pick a method:

**1 — Interactive paste** (simplest, any OS):

```
klaviq bootstrap -ManualPaste
```

Prompts for **key + secret + url** (key/secret hidden — paste them from the App-Identity
page), then lists your accessible vaults so you can **pick a default by name** (optional —
skip it if you only use full `secret://vault/cred` refs). Set `KLAVIQ_HUB_URL` to skip the
url prompt on repeat bootstraps.

**2 — JSON seed file** (automation / CI):

```
klaviq bootstrap -FromJsonFile seed.json -ShredSource
```

`seed.json` = `{"key":"…","secret":"…","url":"https://<tenant>.devolutions.app","vaultId":"…"}`.
`-ShredSource` securely deletes the file afterward.

**3 — Stdin pipe** (no plaintext ever touches disk):

```
<produce-seed-json> | klaviq bootstrap -FromStdin
```

**Sourcing the seed via the Hub API (RDM-free).** If you keep App-Identity creds in a
Hub vault, read them with a dedicated *bootstrap* App Identity over the API and pipe
straight in — no GUI tool in the loop:

```powershell
Import-Module Devolutions.PowerShell
Connect-HubAccount -Url $url -ApplicationKey $bootKey -ApplicationSecret $bootSecret
$e = Get-HubEntryResolved -VaultId $bootstrapVault -EntryId $entryId -ResolveSensitives -ResolvePasswords
$seed = @{ key = $e.…; secret = $e.…; url = $url; vaultId = $vaultGuid } | ConvertTo-Json -Compress
$seed | klaviq bootstrap -FromStdin
Disconnect-HubAccount
```

**Linux (remote host).** Produce the seed on any box that can read the creds, pipe it
to the host over SSH, and bootstrap there (the host needs `age` installed):

```bash
echo '<base64-seed>' | ssh user@host 'base64 -d | pwsh -File ~/klaviq/klaviq.ps1 bootstrap -FromStdin'
```

**Verify:** `klaviq status` → expect `hub-reachable: true` with your vault listed under
`vaults-accessible`.

## 4. Usage — the verbs

**`get`** — resolve one reference to stdout (value bytes only, no trailing newline):

```
klaviq get secret://prod/db-password
```

**`run`** — inject references as env vars, exec a child, pass through its exit code:

```
klaviq run DB_PASSWORD=secret://prod/db-password API_KEY=secret://prod/api-stripe -- ./myapp
```

**`list`** — enumerate vaults, or entries within a vault:

```
klaviq list
klaviq list --vault prod
```

**`status`** — diagnostic snapshot (auth blob, Hub reachability, accessible vaults):

```
klaviq status
```

**`deploy`** — materialize manifest secrets to files and (on Linux) recycle a
docker-compose service:

```
klaviq deploy ./my-service                # reads ./my-service/.klaviq.yml
klaviq deploy ./my-service -NoRecreate    # refresh secret files without recycling
```

## 5. Reference syntax

```
secret://<vault>/<cred>
```

- Exactly one `/` between vault and cred (each is a single segment).
- Either segment may be a human-readable **name** or a 36-char **GUID**, and the
  two may be mixed:
  - `secret://prod/db-password`
  - `secret://7f3c0a1b-…-…/db-password`
- Use the GUID form to disambiguate when names collide.

## 6. Deploy manifest

`deploy` reads `<service-dir>/.klaviq.yml`:

```yaml
secrets:
  - secret://prod/token-grafana-db
  - secret://prod/api-cloudflare-zone
  - 00000000-0000-0000-0000-000000000000   # bare GUID → resolves against the auth blob's default vault
```

Each secret is written atomically (owner-only) to the materialization root —
`/run/klaviq/<name>` on Linux or `%LOCALAPPDATA%\klaviq\runtime\<name>` on Windows
(overridable with `KLAVIQ_SECRET_DIR`). `<name>` is the entry name, so it lines up
with a docker-compose `secrets:` entry.

## 7. Credential types

klaviq extracts the value based on the Hub entry's credential type:

| Hub CredentialType | Field used |
|---|---|
| AccessCode (Secret) | password |
| Default | password |
| ApiKey | API key |
| Custom | custom-script blob (for large/multi-line values, e.g. an SA JSON or PEM) |

Unknown types fail loudly rather than guessing.

## 8. Exit codes

| Code | Meaning |
|---|---|
| 0 | ok |
| 1 | generic failure |
| 2 | reference not found |
| 3 | access denied |
| 4 | vault unreachable |
| 5 | bootstrap blob missing |

On success, `run` passes through the child process's own exit code.

## 9. Security model

- **Stores nothing.** No secret database, no server, no API. Values are fetched
  live per invocation and never cached between fetches.
- **One thing at rest:** the auth blob — the credentials klaviq needs to reach
  your vault — OS-encrypted and bound to the current user/host (DPAPI on Windows,
  `age` on Linux).
- **Never logs secret values.** stdout carries a value only when you explicitly
  `get` it; all diagnostics go to stderr.
- **Memory hygiene:** decrypted material is scrubbed from process memory after use.
- The hard custody problem — storing and encrypting your secrets — belongs to your
  vault, not to klaviq.

## 10. Troubleshooting

| Symptom | Fix |
|---|---|
| `Devolutions.PowerShell module not installed` | `Install-Module Devolutions.PowerShell -Scope CurrentUser` |
| `age is not installed` (Linux) | install `age` (e.g. `apt install age`) |
| exit 5, `no auth blob found` | run `klaviq bootstrap` to seed the App Identity |
| `decrypt failed … different user/machine` | the blob is bound to the user+host that created it — re-bootstrap on this host |
| exit 3 (access denied) | the App Identity isn't scoped to that vault/entry — check its Hub permissions |
| exit 4 (unreachable) | network or Hub-URL issue; `klaviq status` reports `hub-reachable` |
| no **Application identities** in the Hub portal | you're on Hub *Personal*, not *Business* — App Identities are a Hub Business feature (the free tier has them) |

---

klaviq is a personal tool, published as-is. Issues and PRs welcome; no support is promised.
