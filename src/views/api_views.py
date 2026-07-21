"""API views: kernel management, config management, protocol deployment, inbounds."""

import json
import hashlib
import hmac
import logging
from pathlib import Path
from flask import Blueprint, request, jsonify, current_app, session
from .auth_views import login_required, csrf_protected

logger = logging.getLogger(__name__)

api_bp = Blueprint("api", __name__, url_prefix="/api")


def _get_body() -> dict:
    """Safely get JSON request body, always returning a dict."""
    body = request.get_json(silent=True)
    if isinstance(body, dict):
        return body
    return {}


def get_app_components():
    """Get all application components from the app config."""
    return {
        "kernel_mgr": current_app.config["kernel_manager"],
        "config_mgr": current_app.config["config_manager"],
        "process_mgr": current_app.config["process_manager"],
        "wizard": current_app.config["deployment_wizard"],
        "quick_deployment": current_app.config["quick_deployment"],
        "auth_mgr": current_app.config["auth_manager"],
        "app_config": current_app.config["app_config"],
    }


# ---- Kernel API ----

@api_bp.route("/kernel/detect", methods=["POST"])
@login_required
def kernel_detect():
    comp = get_app_components()
    kernel_mgr = comp["kernel_mgr"]

    data = _get_body()
    search_paths = data.get("paths", [])

    try:
        info = kernel_mgr.detect_kernel(search_paths)
        if info:
            return jsonify({
                "found": True,
                "path": str(info.path),
                "version": info.version,
            })
        return jsonify({"found": False})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@api_bp.route("/kernel/set-path", methods=["POST"])
@login_required
@csrf_protected
def kernel_set_path():
    comp = get_app_components()
    kernel_mgr = comp["kernel_mgr"]
    kernel_store = current_app.config["kernel_store"]

    data = _get_body()
    path_str = data.get("path", "")

    if not path_str:
        return jsonify({"error": "Path required"}), 400

    from ..platform import resolve_executable_path
    resolved = resolve_executable_path(path_str)
    if not resolved:
        return jsonify({"error": "sing-box executable not found"}), 400

    version = kernel_mgr.get_version(resolved)
    if not version:
        return jsonify({"error": "Failed to get version from executable"}), 400

    existing = kernel_store.get_by_version(version)
    if existing:
        kernel_store.set_active(version)
    else:
        kernel_store.add_version(version, str(resolved), is_active=True)

    return jsonify({
        "success": True,
        "version": version,
        "path": str(resolved),
    })


@api_bp.route("/kernel/version", methods=["GET"])
@login_required
def kernel_version():
    comp = get_app_components()
    kernel_mgr = comp["kernel_mgr"]
    kernel_store = current_app.config["kernel_store"]

    active = kernel_store.get_active()
    if not active:
        detected = kernel_mgr.detect_kernel()
        if detected:
            kernel_store.add_version(detected.version, str(detected.path), is_active=True)
            active = kernel_store.get_by_version(detected.version)

    if not active:
        return jsonify({"version": None, "path": None})

    actual_version = kernel_mgr.get_version(Path(active["path"]))
    return jsonify({
        "version": actual_version or active["version"],
        "path": active["path"],
        "is_pinned": bool(active.get("is_pinned", 0)),
    })


@api_bp.route("/kernel/versions", methods=["GET"])
@login_required
def kernel_versions():
    kernel_store = current_app.config["kernel_store"]
    versions = kernel_store.get_all()
    return jsonify({"versions": versions})


@api_bp.route("/kernel/switch", methods=["POST"])
@login_required
@csrf_protected
def kernel_switch():
    kernel_store = current_app.config["kernel_store"]
    data = _get_body()
    version = data.get("version", "")

    if not version:
        return jsonify({"error": "Version required"}), 400
    if not kernel_store.has_version(version):
        return jsonify({"error": "Version not installed"}), 404

    kernel_store.set_active(version)
    return jsonify({"success": True})


@api_bp.route("/kernel/pin", methods=["POST"])
@login_required
@csrf_protected
def kernel_pin():
    kernel_store = current_app.config["kernel_store"]
    data = _get_body()
    version = data.get("version", "")
    pinned = data.get("pinned", True)

    if not kernel_store.has_version(version):
        return jsonify({"error": "Version not installed"}), 404

    kernel_store.set_pinned(version, pinned)
    return jsonify({"success": True})


@api_bp.route("/kernel/check-update", methods=["GET"])
@login_required
def kernel_check_update():
    comp = get_app_components()
    kernel_mgr = comp["kernel_mgr"]
    kernel_store = current_app.config["kernel_store"]

    active = kernel_store.get_active()
    if not active:
        return jsonify({"error": "No active kernel"}), 400

    update = kernel_mgr.check_update(active["version"])
    return jsonify({"current": active["version"], "update": update})


@api_bp.route("/kernel/download", methods=["POST"])
@login_required
@csrf_protected
def kernel_download():
    comp = get_app_components()
    kernel_mgr = comp["kernel_mgr"]
    kernel_store = current_app.config["kernel_store"]

    data = _get_body()
    version = data.get("version", "")

    if not version:
        return jsonify({"error": "Version required"}), 400

    try:
        path = kernel_mgr.download_version(version)
        kernel_store.add_version(version, str(path), is_active=False)
        return jsonify({"success": True, "version": version, "path": str(path)})
    except Exception as e:
        logger.error("Download failed: %s", e)
        return jsonify({"error": f"Download failed: {e}"}), 500


@api_bp.route("/kernel/download-latest", methods=["POST"])
@login_required
@csrf_protected
def kernel_download_latest():
    comp = get_app_components()
    kernel_mgr = comp["kernel_mgr"]
    kernel_store = current_app.config["kernel_store"]

    try:
        releases = kernel_mgr.fetch_releases(include_prerelease=False)
        if not releases:
            return jsonify({"error": "Cannot fetch releases from GitHub"}), 502

        latest = releases[0]["version"]
        path = kernel_mgr.download_version(latest)
        kernel_store.add_version(latest, str(path), is_active=True)
        return jsonify({"success": True, "version": latest, "path": str(path)})
    except Exception as e:
        logger.error("Download latest failed: %s", e)
        return jsonify({"error": f"Download failed: {e}"}), 500


# ---- Process API ----

@api_bp.route("/process/status", methods=["GET"])
@login_required
def process_status():
    comp = get_app_components()
    process_mgr = comp["process_mgr"]
    kernel_store = current_app.config["kernel_store"]

    state = process_mgr.status()
    active = kernel_store.get_active()

    return jsonify({
        "running": state.running,
        "pid": state.pid,
        "config_path": state.config_path,
        "kernel_path": state.kernel_path or (active["path"] if active else ""),
        "started_at": state.started_at,
        "kernel_version": active["version"] if active else None,
    })


@api_bp.route("/process/start", methods=["POST"])
@login_required
@csrf_protected
def process_start():
    comp = get_app_components()
    process_mgr = comp["process_mgr"]
    config_mgr = comp["config_mgr"]
    kernel_store = current_app.config["kernel_store"]
    app_config = comp["app_config"]

    active = kernel_store.get_active()
    if not active:
        return jsonify({"error": "No active kernel configured"}), 400

    kernel_path = Path(active["path"])
    config_path = config_mgr.config_path
    log_path = app_config.log_dir / "sing-box.log"

    try:
        state = process_mgr.start(kernel_path, config_path, log_path)
        return jsonify({
            "success": True,
            "running": state.running,
            "pid": state.pid,
        })
    except RuntimeError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@api_bp.route("/process/stop", methods=["POST"])
@login_required
@csrf_protected
def process_stop():
    comp = get_app_components()
    process_mgr = comp["process_mgr"]

    try:
        state = process_mgr.stop()
        return jsonify({
            "success": True,
            "running": state.running,
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@api_bp.route("/process/restart", methods=["POST"])
@login_required
@csrf_protected
def process_restart():
    comp = get_app_components()
    process_mgr = comp["process_mgr"]
    config_mgr = comp["config_mgr"]
    kernel_store = current_app.config["kernel_store"]
    app_config = comp["app_config"]

    active = kernel_store.get_active()
    if not active:
        return jsonify({"error": "No active kernel configured"}), 400

    kernel_path = Path(active["path"])
    config_path = config_mgr.config_path
    log_path = app_config.log_dir / "sing-box.log"

    try:
        state = process_mgr.restart(kernel_path, config_path, log_path)
        return jsonify({
            "success": True,
            "running": state.running,
            "pid": state.pid,
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ---- Config API ----

@api_bp.route("/config", methods=["GET"])
@login_required
def config_get():
    comp = get_app_components()
    config_mgr = comp["config_mgr"]
    from ..utils import mask_sensitive

    try:
        if config_mgr.exists:
            raw = config_mgr.config_path.read_text("utf-8")
            config = json.loads(raw)
            masked_raw = mask_sensitive(raw)
        else:
            config = config_mgr.read()
            masked_raw = json.dumps(config, indent=2)
        return jsonify({"config": config, "raw": masked_raw})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@api_bp.route("/config", methods=["PUT"])
@login_required
@csrf_protected
def config_update():
    comp = get_app_components()
    config_mgr = comp["config_mgr"]
    kernel_store = current_app.config["kernel_store"]

    data = _get_body()
    config = data.get("config")

    if not config:
        return jsonify({"error": "Config required"}), 400

    active = kernel_store.get_active()
    kernel_path = Path(active["path"]) if active else None

    ok, msg = config_mgr.set_config(config, kernel_path)
    if not ok:
        return jsonify({"error": msg}), 400

    return jsonify({"success": True, "message": msg})


@api_bp.route("/config/check", methods=["POST"])
@login_required
def config_check():
    comp = get_app_components()
    config_mgr = comp["config_mgr"]
    kernel_mgr = comp["kernel_mgr"]
    kernel_store = current_app.config["kernel_store"]

    active = kernel_store.get_active()
    if not active:
        return jsonify({"error": "No active kernel"}), 400

    data = _get_body()
    config = data.get("config")

    import tempfile
    tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
    try:
        json.dump(config or config_mgr.read(), tmp)
        tmp.close()

        kernel_path = Path(active["path"])
        ok, msg = kernel_mgr.check_config(kernel_path, Path(tmp.name))
        return jsonify({"valid": ok, "message": msg})
    finally:
        Path(tmp.name).unlink(missing_ok=True)


@api_bp.route("/config/backups", methods=["GET"])
@login_required
def config_backups():
    comp = get_app_components()
    config_mgr = comp["config_mgr"]
    backups = config_mgr.list_backups()
    return jsonify({"backups": backups})


@api_bp.route("/config/backup", methods=["POST"])
@login_required
@csrf_protected
def config_backup():
    comp = get_app_components()
    config_mgr = comp["config_mgr"]

    data = _get_body()
    description = data.get("description", "manual")

    try:
        name = config_mgr.backup(description)
        return jsonify({"success": True, "backup": name})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@api_bp.route("/config/restore", methods=["POST"])
@login_required
@csrf_protected
def config_restore():
    comp = get_app_components()
    config_mgr = comp["config_mgr"]
    kernel_store = current_app.config["kernel_store"]

    data = _get_body()
    backup_name = data.get("backup", "")

    if not backup_name:
        return jsonify({"error": "Backup name required"}), 400

    active = kernel_store.get_active()
    kernel_path = Path(active["path"]) if active else None

    ok, msg = config_mgr.restore(backup_name, kernel_path)
    if not ok:
        return jsonify({"error": msg}), 400

    return jsonify({"success": True, "message": msg})


# ---- Protocol API ----

@api_bp.route("/protocols", methods=["GET"])
@login_required
def protocols_list():
    comp = get_app_components()
    wizard = comp["wizard"]
    protocols = wizard.get_available_protocols()
    return jsonify({"protocols": protocols})


@api_bp.route("/protocols/<ptype>", methods=["GET"])
@login_required
def protocol_schema(ptype):
    comp = get_app_components()
    wizard = comp["wizard"]
    schema = wizard.get_protocol_schema(ptype)
    if not schema:
        return jsonify({"error": "Protocol not found"}), 404
    return jsonify({"protocol": schema})


@api_bp.route("/protocols/<ptype>/defaults", methods=["GET"])
@login_required
def protocol_defaults(ptype):
    comp = get_app_components()
    wizard = comp["wizard"]
    try:
        defaults = wizard.generate_defaults(ptype)
        return jsonify({"defaults": defaults})
    except ValueError as e:
        return jsonify({"error": str(e)}), 400


@api_bp.route("/protocols/validate", methods=["POST"])
@login_required
def protocol_validate():
    comp = get_app_components()
    wizard = comp["wizard"]

    data = _get_body()
    protocol_type = data.get("type", "")
    params = data.get("params", {})

    errors = wizard.validate_params(protocol_type, params)
    if errors:
        return jsonify({"valid": False, "errors": errors})

    conflicts = wizard.check_deployment_conflicts(protocol_type, params)
    if conflicts:
        return jsonify({"valid": False, "errors": conflicts})

    return jsonify({"valid": True})


@api_bp.route("/protocols/preview", methods=["POST"])
@login_required
def protocol_preview():
    comp = get_app_components()
    wizard = comp["wizard"]

    data = _get_body()
    protocol_type = data.get("type", "")
    params = data.get("params", {})

    errors = wizard.validate_params(protocol_type, params)
    if errors:
        return jsonify({"error": "; ".join(errors)}), 400

    try:
        preview = wizard.generate_preview(protocol_type, params)
        diff = wizard.generate_diff(preview)
        return jsonify({"preview": preview, "diff": diff})
    except ValueError as e:
        return jsonify({"error": str(e)}), 400


@api_bp.route("/protocols/deploy", methods=["POST"])
@login_required
@csrf_protected
def protocol_deploy():
    comp = get_app_components()
    wizard = comp["wizard"]
    config_mgr = comp["config_mgr"]
    kernel_store = current_app.config["kernel_store"]

    data = _get_body()
    protocol_type = data.get("type", "")
    params = data.get("params", {})
    restart = data.get("restart", True)

    active = kernel_store.get_active()
    if not active:
        return jsonify({"error": "No active kernel configured"}), 400

    kernel_path = Path(active["path"])
    config_path = config_mgr.config_path

    result = wizard.deploy(protocol_type, params, kernel_path, config_path, restart)

    if not result["success"]:
        return jsonify({"error": result["message"]}), 400

    return jsonify(result)


@api_bp.route("/quick-deploy", methods=["POST"])
@login_required
@csrf_protected
def quick_deploy():
    """Atomically deploy every protocol supported by the supplied endpoints."""
    comp = get_app_components()
    config_mgr = comp["config_mgr"]
    kernel_store = current_app.config["kernel_store"]
    active = kernel_store.get_active()
    if not active:
        return jsonify({"error": "No active kernel configured"}), 400

    data = _get_body()
    try:
        result = comp["quick_deployment"].deploy(
            data,
            Path(active["path"]),
            config_mgr.config_path,
            kernel_version=str(active.get("version", "")),
            restart=data.get("restart", True),
        )
    except Exception as exc:
        logger.exception("Quick deployment failed")
        return jsonify({"error": f"Quick deployment failed: {exc}"}), 500
    if not result["success"]:
        return jsonify({"error": result["message"], **result}), 400
    return jsonify(result)


# ---- Inbounds API ----

@api_bp.route("/inbounds", methods=["GET"])
@login_required
def inbounds_list():
    comp = get_app_components()
    config_mgr = comp["config_mgr"]
    process_mgr = comp["process_mgr"]
    from ..analyzer import analyze_inbounds, mask_sensitive_inbound_info
    from ..config_mgr import json_load_keep_unknown

    try:
        config = config_mgr.read() if config_mgr.exists else {"inbounds": []}
    except Exception:
        config = {"inbounds": []}

    state = process_mgr.status()
    running = state.running

    endpoint_profile = comp["app_config"].public_endpoints
    inbounds = analyze_inbounds(
        config,
        running,
        endpoint_profile=endpoint_profile,
        endpoint_profiles=comp["app_config"].inbound_endpoint_profiles,
    )
    masked = [mask_sensitive_inbound_info(info) for info in inbounds]

    return jsonify({"inbounds": masked})


@api_bp.route("/inbounds/<tag>", methods=["GET"])
@login_required
def inbound_detail(tag):
    comp = get_app_components()
    config_mgr = comp["config_mgr"]
    process_mgr = comp["process_mgr"]

    config = config_mgr.read()
    inbounds = config.get("inbounds", [])

    inbound = None
    for ib in inbounds:
        if ib.get("tag") == tag:
            inbound = ib
            break

    if not inbound:
        return jsonify({"error": "Inbound not found"}), 404

    state = process_mgr.status()

    from ..analyzer import analyze_single_inbound, mask_sensitive_inbound_info
    info = analyze_single_inbound(
        inbound,
        state.running,
        endpoint_profile=(
            comp["app_config"].inbound_endpoint_profiles.get(tag)
            or comp["app_config"].public_endpoints
        ),
    )

    return jsonify({"inbound": mask_sensitive_inbound_info(info)})


@api_bp.route("/inbounds/<tag>", methods=["DELETE"])
@login_required
@csrf_protected
def inbound_delete(tag):
    comp = get_app_components()
    config_mgr = comp["config_mgr"]
    kernel_store = current_app.config["kernel_store"]

    active = kernel_store.get_active()
    kernel_path = Path(active["path"]) if active else None

    ok, msg = config_mgr.remove_inbound(tag, kernel_path)
    if not ok:
        return jsonify({"error": msg}), 400

    comp["app_config"].remove_inbound_endpoint_profile(tag)

    return jsonify({"success": True, "message": msg})


# ---- Platform API ----

@api_bp.route("/platform", methods=["GET"])
@login_required
def platform_info():
    from ..platform import detect_platform_info, check_capabilities
    info = detect_platform_info()
    caps = check_capabilities()
    return jsonify({"platform": info, "capabilities": caps})


# ---- Operation Log API ----

@api_bp.route("/logs", methods=["GET"])
@login_required
def operation_logs():
    log_store = current_app.config["operation_log_store"]
    logs = log_store.get_recent(100)
    return jsonify({"logs": logs})


@api_bp.route("/logs/singbox", methods=["GET"])
@login_required
def singbox_logs():
    comp = get_app_components()
    app_config = comp["app_config"]
    log_path = app_config.log_dir / "sing-box.log"

    if log_path.exists():
        try:
            with open(log_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
            from ..utils import mask_sensitive
            return jsonify({"log": mask_sensitive(content[-100000:])})
        except Exception as e:
            return jsonify({"error": str(e)}), 500
    return jsonify({"log": ""})


# ---- Settings API ----

@api_bp.route("/settings", methods=["GET"])
@login_required
def settings_get():
    comp = get_app_components()
    app_config = comp["app_config"]
    return jsonify({
        "listen_host": app_config.listen_host,
        "listen_port": app_config.listen_port,
        "session_duration_minutes": app_config.session_duration_minutes,
        "login_max_attempts": app_config.login_max_attempts,
        "data_dir": str(app_config.data_dir),
        "config_file": str(app_config.config_file_path),
        "lang": request.cookies.get("sh_lang", "en"),
        "public_endpoints": app_config.public_endpoints,
        "cloudflare_zone_id": app_config.cloudflare_zone_id,
    })


@api_bp.route("/settings/public-endpoints", methods=["PUT"])
@login_required
@csrf_protected
def settings_public_endpoints():
    from ..endpoints import build_endpoint_profile

    data = _get_body()
    profile, errors = build_endpoint_profile(data)
    if errors:
        return jsonify({"error": "; ".join(errors), "errors": errors}), 400

    app_config = current_app.config["app_config"]
    app_config.set_public_endpoints(profile, data.get("cloudflare_zone_id", ""))
    return jsonify({
        "success": True,
        "public_endpoints": profile,
        "cloudflare_zone_id": app_config.cloudflare_zone_id,
    })


@api_bp.route("/cloudflare/dns/preview", methods=["POST"])
@login_required
def cloudflare_dns_preview():
    from ..cloudflare import build_dns_plan

    data = _get_body()
    plan, errors = build_dns_plan(data)
    if errors:
        return jsonify({"error": "; ".join(errors), "errors": errors}), 400
    preview_token = hashlib.sha256(
        json.dumps(plan, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    session["cloudflare_dns_preview"] = preview_token
    return jsonify({"success": True, "plan": plan, "preview_token": preview_token})


@api_bp.route("/cloudflare/dns/sync", methods=["POST"])
@login_required
@csrf_protected
def cloudflare_dns_sync():
    from ..cloudflare import CloudflareError, build_dns_plan, sync_dns_records

    data = _get_body()
    plan, errors = build_dns_plan(data)
    if errors:
        return jsonify({"error": "; ".join(errors), "errors": errors}), 400
    expected = hashlib.sha256(
        json.dumps(plan, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    supplied = str(data.get("preview_token", ""))
    session_token = str(session.get("cloudflare_dns_preview", ""))
    if not supplied or not hmac.compare_digest(supplied, expected) or not hmac.compare_digest(supplied, session_token):
        return jsonify({"error": "Preview the current DNS changes before synchronizing"}), 409
    try:
        result = sync_dns_records(data)
    except CloudflareError as exc:
        return jsonify({"error": str(exc)}), 400
    session.pop("cloudflare_dns_preview", None)

    app_config = current_app.config["app_config"]
    from ..endpoints import build_endpoint_profile
    profile, _ = build_endpoint_profile(data)
    app_config.set_public_endpoints(profile, data.get("zone_id", ""))
    return jsonify(result)


@api_bp.route("/settings/lang", methods=["POST"])
def settings_lang():
    data = _get_body()
    lang = data.get("lang", "en")
    if lang not in ("en", "zh"):
        lang = "en"
    resp = jsonify({"success": True, "lang": lang})
    resp.set_cookie("sh_lang", lang, max_age=31536000, httponly=False, samesite="Lax", path="/")
    return resp
