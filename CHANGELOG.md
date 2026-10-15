# Changelog

All notable changes to the ASMBS SSO plugin will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.9] - 2026-10-15
### Changed
- Revised msql to also get membership.product.code and set that to mem_type for wordpress users on login

## [1.0.8] - 2026-09-11
### Changed
- `vote_md` / `vote_ih` capability grants now match on `Membership.Product` GUID instead of `Membership.Type.name` string, so a product rename in MemberSuite no longer silently breaks voting access

## [1.0.7] - 2026-08-17
### Added
- SSO plugin now grants/revokes a `view_member_content` capability based on `Membership.ReceivesMemberBenefits`, evaluated on both account creation and every subsequent login (same signal already used for `vote_md`/`vote_ih`).

## [1.0.6] - 2026-04-28
### Added
- Github actions to rebuild packagist

## [1.0.5] - 2026-04-22
### Added
- Shortcodes.php
- Shortcode support for SSO form (including javascript)

## [1.0.4] - 2026-04-21
### Fixed
- Settings page

## [1.0.3] - 2026-04-21
### Fixed
- Updated formatting
- Updated functions to support settings page

### Added
- Settings page in WP admin

## [1.0.2] - 2026-04-21
### Fixed
- Renewal membership types now correctly resolve to the same WordPress role as their base type
- `resolveType()` now correctly maps renewal types to their `mem_type` shortcode (e.g. `Integrated Health Renewal` → `IH`)
- Staff accounts with null membership type no longer cause a fatal error in `resolveWPRole()`

## [1.0.2] - 2026-04-21
### Fixed
- Bug fixes

## [1.0.0] - 2026-04-21
### Added
- Initial release — SSO logic migrated from `login-next-url.php` theme template to standalone plugin
- `SSO` class handles full authentication flow via `template_redirect` hook
- `RoleResolver` class maps MemberSuite membership types and benefit status to WordPress roles
- User lookup by MemberSuite GUID, local ID, and email with fallback account creation
- Role and capability assignment for `vote_md` and `vote_ih` based on membership type
- Meta backfilling for `mem_guid`, `mem_key`, `mem_status`, `mem_type` on login
- Staff accounts with no membership record preserve their existing WordPress role
- SSO activity logged to `/tmp/sso-debug.log`
- Guzzle HTTP client for MemberSuite API calls
- PSR-4 autoloading under `ASMBS\SSO` namespace