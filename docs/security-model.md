# SingHarbor Security Model

## Authentication

- **Password**: bcrypt hashed with work factor 12
- **Session**: HTTP-only cookie, signed, with expiration
- **CSRF**: HMAC-based double-submit cookie pattern
- **Login Protection**: Rate limiting by IP (5 attempts, 15 min lockout)

## Network

- **Default bind**: 127.0.0.1 only
- **Protocol**: HTTP (no built-in HTTPS)
- **Warning**: Non-localhost binding displays security warning
- **Recommendation**: Use HTTPS reverse proxy for remote access

## Data Protection

- Sensitive fields (password, uuid, private_key) are masked in:
  - Logs
  - API responses (by default)
  - WebUI display (click-to-reveal)
- sing-box config backup before every modification
- Atomic file writes (temp file -> rename)
- Cloudflare API tokens are never persisted or returned by API responses
- Cloudflare DNS writes require authentication, CSRF validation, preview, and explicit confirmation

## Path Security

- Path sandbox restricts file operations to configured directories
- Directory traversal prevention
- Executable path validation

## Command Execution

- All external commands use list-based args (no shell injection)
- Command timeout enforcement
- No arbitrary command execution API
- Only predefined sing-box commands

## Attack Surface

- No user registration
- No file upload (except kernel download with GitHub URL only)
- No arbitrary path read/write
- Minimal exposed endpoints

## Not Implemented (User Responsibility)

- HTTPS/TLS for WebUI
- Firewall configuration
- Non-Cloudflare DNS providers
- Certificate management (ACME)
- Reverse proxy setup
