# SingHarbor Architecture

## Overview

SingHarbor is a WebUI for managing personal sing-box instances.

```
┌─────────────────────────────────────────────┐
│                Web Browser                   │
│         (HTML/CSS/JavaScript)                │
└──────────────────┬──────────────────────────┘
                   │ HTTP (127.0.0.1:8080)
┌──────────────────▼──────────────────────────┐
│              Flask Application               │
│  ┌──────────┐ ┌──────────┐ ┌──────────────┐ │
│  │ Auth Views│ │ API Views│ │   UI Views   │ │
│  └────┬─────┘ └────┬─────┘ └──────┬───────┘ │
│       │             │              │          │
│  ┌────▼─────────────▼──────────────▼───────┐ │
│  │          Core Services                  │ │
│  │  ┌──────┐ ┌──────┐ ┌──────┐ ┌───────┐  │ │
│  │  │ Auth │ │Kernel│ │Config│ │Wizard │  │ │
│  │  └──┬───┘ └──┬───┘ └──┬───┘ └───┬───┘  │ │
│  │     │        │        │         │       │ │
│  │  ┌──▼────────▼────────▼─────────▼─────┐ │ │
│  │  │         Protocol Layer             │ │ │
│  │  └────────────────────────────────────┘ │ │
│  └────────────────────────────────────────┘ │
│  ┌────────────────────────────────────────┐ │
│  │           Platform Layer               │ │
│  │  (OS detection, paths, process mgmt)   │ │
│  └────────────────────────────────────────┘ │
└──────────────────┬──────────────────────────┘
                   │
     ┌─────────────┼─────────────┐
     │             │              │
┌────▼────┐ ┌──────▼──────┐ ┌───▼──────┐
│  SQLite  │ │ Config JSON │ │ sing-box │
│   (DB)   │ │   (Files)   │ │ (Process)│
└─────────┘ └─────────────┘ └──────────┘
```

## Component Descriptions

### Auth Module
- Single admin account system
- bcrypt password hashing
- Session-based authentication (HTTP-only cookies)
- CSRF protection (HMAC tokens)
- Login failure rate limiting

### Kernel Manager
- sing-box executable detection
- Version querying
- Multi-version management
- GitHub release download
- Version switching and pinning

### Process Manager
- Platform-specific process lifecycle
- Start/stop/restart operations
- PID tracking
- Cross-platform signal handling

### Config Manager
- JSON configuration read/write
- Backup and restore
- Configuration history
- Diff computation
- Atomic save with validation
- Unknown field preservation

### Protocol Layer
- Protocol definition classes
- Parameter validation
- Config generation
- Client info generation
- Share link creation

### Deployment Wizard
- Multi-step deployment flow
- Conflict checking
- Config preview
- Kernel validation
- Safe deployment with rollback

### Platform Layer
- OS and architecture detection
- Executable naming
- Archive format selection
- Permission detection
- Capability reporting

## Data Flow

### sing-box Configuration
- sing-box config files are the source of truth
- SingHarbor DB stores metadata only
- All config changes go through: backup -> validate -> atomic save -> restart

### Shared Conventions
- `inbounds` array holds all server proxy protocols
- Each inbound uses official sing-box field names
- Unknown fields are preserved during reads/writes
