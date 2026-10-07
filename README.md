# Whoogle Search: SSRF and config-name path traversal (CVE-2024-22203, -22204, -22205)

Case study of three advisories in [benbusby/whoogle-search](https://github.com/benbusby/whoogle-search), all fixed
by one commit: two Flask routes fetch a caller-supplied URL server-side (CWE-918), and a third joins a
caller-supplied file name onto the config directory before reading or writing a pickle (CWE-22).

> **Demo only, not for use.** This repository is a case study built from unmodified snapshots of
> [benbusby/whoogle-search](https://github.com/benbusby/whoogle-search) at two historical commits. It is not a fork and is not maintained. Do not install, deploy, or
> depend on it: the `baseline` branch contains code affected by the advisories below.

**This branch: `main`** holds only this index. The code is on [`baseline`](https://github.com/ferralon-demo/whoogle-search-ssrf-path-traversal/tree/baseline) (tag `poe`, vulnerable) and [`fix`](https://github.com/ferralon-demo/whoogle-search-ssrf-path-traversal/tree/fix) (tag `pone`, patched).

## Advisories

| CVE | GHSA | CWE | Handler |
|---|---|---|---|
| [CVE-2024-22203](https://nvd.nist.gov/vuln/detail/CVE-2024-22203) | [GHSA-q97g-c29h-x2p7](https://github.com/advisories/GHSA-q97g-c29h-x2p7) | CWE-918 (the GHSA title says "Path Traversal"; its description and CWE are SSRF) | `element` |
| [CVE-2024-22205](https://nvd.nist.gov/vuln/detail/CVE-2024-22205) | [GHSA-3q6g-qmpx-rqw4](https://github.com/advisories/GHSA-3q6g-qmpx-rqw4) | CWE-918 | `window` |
| [CVE-2024-22204](https://nvd.nist.gov/vuln/detail/CVE-2024-22204) | [GHSA-hh2q-qv66-jcqg](https://github.com/advisories/GHSA-hh2q-qv66-jcqg) | CWE-22 | `config` |

All three: affected `whoogle-search` < 0.8.4 per GHSA; upstream fix commit
[`3a2e0b262e`](https://github.com/benbusby/whoogle-search/commit/3a2e0b262e4a076a20416b45e6b6f23fd265aeda),
"Validate urls in `element` and `window` endpoints", 2023-09-13 (pushed directly; no pull request). The
advisories cite line numbers at an earlier upstream commit (`92e8ede24e`); the line numbers below are at this
snapshot.

## Ingress and sink at `baseline`

All line numbers are at upstream commit `8830615abc`. Route paths are f-strings over the `Endpoint` enum
([`app/models/endpoint.py`](https://github.com/benbusby/whoogle-search/blob/8830615abcf17e0cd3991fbf963debfb161784cd/app/models/endpoint.py)): `/element`, `/window`, `/config`.

| Advisory | Ingress | Sink |
|---|---|---|
| CVE-2024-22203 | `@app.route(f'/{Endpoint.element}')` on `element`, [`app/routes.py:462-465`](https://github.com/benbusby/whoogle-search/blob/8830615abcf17e0cd3991fbf963debfb161784cd/app/routes.py#L462-L465); query arg `url` | `g.user_request.send(base_url=src_url)` at [`routes.py:479`](https://github.com/benbusby/whoogle-search/blob/8830615abcf17e0cd3991fbf963debfb161784cd/app/routes.py#L479) → `Request.send` [`app/request.py:271`](https://github.com/benbusby/whoogle-search/blob/8830615abcf17e0cd3991fbf963debfb161784cd/app/request.py#L271) → `requests.get(...)` [`request.py:339`](https://github.com/benbusby/whoogle-search/blob/8830615abcf17e0cd3991fbf963debfb161784cd/app/request.py#L339) |
| CVE-2024-22205 | `@app.route(f'/{Endpoint.window}')` on `window`, [`app/routes.py:493-496`](https://github.com/benbusby/whoogle-search/blob/8830615abcf17e0cd3991fbf963debfb161784cd/app/routes.py#L493-L496); query arg `location` | `g.user_request.send(base_url=target_url)` at [`routes.py:509`](https://github.com/benbusby/whoogle-search/blob/8830615abcf17e0cd3991fbf963debfb161784cd/app/routes.py#L509) → same `Request.send` → `requests.get` |
| CVE-2024-22204 | `@app.route(f'/{Endpoint.config}', methods=['GET', 'POST', 'PUT'])` on `config`, [`app/routes.py:416-419`](https://github.com/benbusby/whoogle-search/blob/8830615abcf17e0cd3991fbf963debfb161784cd/app/routes.py#L416-L419); query arg `name` | `pickle.load(open(config_pkl, 'rb'))` at [`routes.py:430`](https://github.com/benbusby/whoogle-search/blob/8830615abcf17e0cd3991fbf963debfb161784cd/app/routes.py#L430) (PUT) and `pickle.dump(config_data, open(..., 'wb'))` at [`routes.py:443-447`](https://github.com/benbusby/whoogle-search/blob/8830615abcf17e0cd3991fbf963debfb161784cd/app/routes.py#L443-L447) (POST), both on `os.path.join(app.config['CONFIG_PATH'], name)` |

All three handlers are also decorated `@session_required` and `@auth_required`.

## What the fix changes

At `3a2e0b262e` (`app/routes.py` only, +26/−7): `element` and `window` return early unless
`validators.domain(...)` accepts the target's host ([line 489](https://github.com/benbusby/whoogle-search/blob/3a2e0b262e4a076a20416b45e6b6f23fd265aeda/app/routes.py#L489),
[line 521](https://github.com/benbusby/whoogle-search/blob/3a2e0b262e4a076a20416b45e6b6f23fd265aeda/app/routes.py#L521)); `config` normalises `name` and rejects it unless it matches
`^[A-Za-z0-9_.+-]+$` ([line 429](https://github.com/benbusby/whoogle-search/blob/3a2e0b262e4a076a20416b45e6b6f23fd265aeda/app/routes.py#L429)). The calls to `Request.send`
([493](https://github.com/benbusby/whoogle-search/blob/3a2e0b262e4a076a20416b45e6b6f23fd265aeda/app/routes.py#L493), [528](https://github.com/benbusby/whoogle-search/blob/3a2e0b262e4a076a20416b45e6b6f23fd265aeda/app/routes.py#L528)) and to `pickle.load`/`pickle.dump`
([437](https://github.com/benbusby/whoogle-search/blob/3a2e0b262e4a076a20416b45e6b6f23fd265aeda/app/routes.py#L437), [450](https://github.com/benbusby/whoogle-search/blob/3a2e0b262e4a076a20416b45e6b6f23fd265aeda/app/routes.py#L450)) are still present: the fix adds guards and removes
no call.

## Provenance

This is not a fork: a fresh repository whose code branches hold upstream source snapshots, with no upstream
history and no upstream remote.

| Branch | Tag | Upstream commit | Date | Snapshot commit | Snapshot tree |
|---|---|---|---|---|---|
| `baseline` | `poe` | [`8830615abc`](https://github.com/benbusby/whoogle-search/commit/8830615abcf17e0cd3991fbf963debfb161784cd) | 2023-09-13 | `f944a28aaa94119b9f7c6c861528f4a5d9a2d21a` | `290632da676a9b923df7cff528fca0a1531b3a0b` |
| `fix` | `pone` | [`3a2e0b262e`](https://github.com/benbusby/whoogle-search/commit/3a2e0b262e4a076a20416b45e6b6f23fd265aeda) | 2023-09-13 | `f7100f41989274bd57ded9a03830d5c0847751f6` | `325a59cda16cd0c8f93c07d360bd8a5124e1bc39` |

Each snapshot commit is the upstream tree at that commit with one change: `.github/workflows/` (6 files) is
removed so that upstream CI does not run here. No other file is added, removed, or edited. The `fix` snapshot's
parent is the `baseline` snapshot, so the diff between the two snapshot commits
([compare](https://github.com/ferralon-demo/whoogle-search-ssrf-path-traversal/compare/f944a28aaa94119b9f7c6c861528f4a5d9a2d21a...f7100f41989274bd57ded9a03830d5c0847751f6)) is exactly the upstream fix commit's diff. On each code branch, a second
commit replaces upstream's `README.md` with a branch-specific version of this file; upstream's README is in the snapshot commit.

To check a snapshot against upstream from a clone of this repository:

```sh
git fetch https://github.com/benbusby/whoogle-search 8830615abcf17e0cd3991fbf963debfb161784cd
git diff --stat FETCH_HEAD f944a28aaa94119b9f7c6c861528f4a5d9a2d21a   # lists only .github/workflows/*
```

## Tags

| Tag | Commit | Pins |
|---|---|---|
| `poe` | `4dad7ec2953086803b214f364d175e754e8033da` | `baseline`: vulnerable snapshot plus this README |
| `pone` | `96925aee7cb452dd215117bbcf26b8a8cc79b39e` | `fix`: patched snapshot plus this README |

## Licence

Whoogle Search is licensed under the MIT License (`LICENSE`, kept verbatim at the root of the `baseline` and `fix`
branches; upstream ships no `NOTICE` file). Changes made for this case study, on 2026-10-07: `.github/workflows/`
removed, and this `README.md` replaces upstream's.
