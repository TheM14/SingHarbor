# SingHarbor Development Plan

## Current Status

**Version**: 0.1.0 (Phase 1 & 2 MVP)

## Phase 1: Foundation (Completed)

- [x] Project structure and environment setup
- [x] Environment-independent dependency definition (requirements.txt)
- [x] Database schema (SQLite)
- [x] Admin authentication (bcrypt + sessions + CSRF)
- [x] Platform detection and abstraction
- [x] Path security sandbox
- [x] Sensitive data masking

## Phase 2: Core Management (Completed)

- [x] sing-box kernel detection
- [x] Version querying
- [x] Kernel version storage and switching
- [x] Process management (start/stop/restart)
- [x] Configuration read/write
- [x] Backup and restore
- [x] Configuration validation
- [x] Operation logging

## Phase 3: Protocol Wizard (Completed)

- [x] Protocol definition layer
- [x] Shadowsocks wizard
- [x] VMess wizard
- [x] Trojan wizard
- [x] VLESS wizard
- [x] Config preview and diff
- [x] Deployment with validation
- [x] Client connection info generation
- [x] Inbound analysis from existing config

## Phase 4: Extensions (Planned)

- [ ] Kernel download from GitHub releases
- [ ] More protocols (Hysteria2, TUIC, etc.)
- [ ] Inbound management (edit/update)
- [ ] QR code generation for share links
- [ ] Configuration merge (sing-box merge)
- [ ] Advanced transport configuration UI

## Phase 5: Advanced (Planned)

- [ ] Full advanced configuration editing
- [ ] sing-box log viewer with filtering
- [ ] Traffic statistics (if sing-box API available)
- [ ] Optional system service integration
- [ ] More platform edge case handling

## Not Planned

- Multi-user / multi-tenant
- Subscription management
- Bandwidth billing
- Payment integration
- Docker support (user can install themselves)
- Automatic firewall configuration

## Testing Coverage

- Admin initialization and login
- Password change
- Session and CSRF validation
- Platform and architecture detection
- Kernel version database operations
- Configuration backup/restore
- Atomic save and conflict detection
- Protocol parameter validation
- Sensitive data masking
- Path sandbox enforcement
