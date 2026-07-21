"""Process management for sing-box: start, stop, restart, status monitoring.

Uses subprocess.Popen for process lifecycle.
Stores process info (pid, config path, start time) as metadata.
Does NOT depend on systemd, Docker, or Windows Service.
"""

import os
import sys
import time
import signal
import subprocess
import logging
import json
from pathlib import Path
from .sandbox import validate_executable_path

logger = logging.getLogger(__name__)

PROCESS_INFO_FILE = "singbox_process.json"


class ProcessState:
    """Current state of the sing-box process."""
    def __init__(self, running: bool = False, pid: int | None = None,
                 config_path: str = "", kernel_path: str = "",
                 started_at: str = "", version: str = ""):
        self.running = running
        self.pid = pid
        self.config_path = config_path
        self.kernel_path = kernel_path
        self.started_at = started_at
        self.version = version


class ProcessManager:
    """Manages sing-box process lifecycle."""

    def __init__(self, runtime_dir: Path):
        self.runtime_dir = Path(runtime_dir)
        self.runtime_dir.mkdir(parents=True, exist_ok=True)
        self._current: ProcessState | None = None

    @property
    def info_path(self) -> Path:
        return self.runtime_dir / PROCESS_INFO_FILE

    def start(self, kernel_path: Path, config_path: Path,
              log_path: Path | None = None) -> ProcessState:
        """Start sing-box with the given configuration.

        Returns ProcessState on success.
        Raises RuntimeError if already running or start fails.
        """
        validate_executable_path(kernel_path)

        current = self.status()
        if current.running:
            raise RuntimeError(
                f"sing-box is already running (PID: {current.pid})"
            )

        exe = str(kernel_path)
        cmd = [exe, "run", "-c", str(config_path)]

        if log_path:
            log_path.parent.mkdir(parents=True, exist_ok=True)
            log_file = open(log_path, "w")
            stdout = log_file
            stderr = log_file
        else:
            stdout = None
            stderr = None

        try:
            if sys.platform == "win32":
                process = subprocess.Popen(
                    cmd,
                    stdout=stdout or subprocess.DEVNULL,
                    stderr=stderr or subprocess.DEVNULL,
                    creationflags=subprocess.CREATE_NEW_PROCESS_GROUP
                    if hasattr(subprocess, "CREATE_NEW_PROCESS_GROUP")
                    else 0,
                )
            else:
                process = subprocess.Popen(
                    cmd,
                    stdout=stdout,
                    stderr=stderr,
                    start_new_session=True,
                )
        except PermissionError as e:
            raise RuntimeError(
                f"Permission denied starting sing-box: {e}. "
                "Check file permissions or required privileges."
            )
        except Exception as e:
            raise RuntimeError(f"Failed to start sing-box: {e}")

        time.sleep(1)

        if process.poll() is not None:
            raise RuntimeError(
                f"sing-box exited immediately with code {process.returncode}. "
                "Check the configuration and logs."
            )

        state = ProcessState(
            running=True,
            pid=process.pid,
            config_path=str(config_path),
            kernel_path=str(kernel_path),
            started_at=time.strftime("%Y-%m-%d %H:%M:%S"),
        )
        self._save_state(state)
        logger.info("sing-box started with PID %d", process.pid)
        return state

    def stop(self) -> ProcessState:
        """Stop the running sing-box process."""
        current = self.status()
        if not current.running:
            return ProcessState(running=False)

        try:
            if sys.platform == "win32":
                subprocess.run(
                    ["taskkill", "/F", "/PID", str(current.pid)],
                    capture_output=True, timeout=10
                )
            else:
                try:
                    os.killpg(os.getpgid(current.pid), signal.SIGTERM)
                except (ProcessLookupError, OSError):
                    try:
                        os.kill(current.pid, signal.SIGTERM)
                    except (ProcessLookupError, OSError):
                        pass

            time.sleep(0.5)

            for _ in range(10):
                if not self._is_pid_running(current.pid):
                    break
                time.sleep(0.5)
            else:
                self._force_kill(current.pid)
        except Exception as e:
            logger.warning("Error stopping process: %s", e)

        state = ProcessState(running=False)
        self._save_state(state)
        logger.info("sing-box stopped (was PID %d)", current.pid)
        return state

    def restart(self, kernel_path: Path, config_path: Path,
                log_path: Path | None = None) -> ProcessState:
        """Restart sing-box (stop if running, then start)."""
        current = self.status()
        if current.running:
            self.stop()
            time.sleep(1)
        return self.start(kernel_path, config_path, log_path)

    def status(self) -> ProcessState:
        """Check if sing-box is running and return the process state."""
        if self._current and self._current.running:
            if self._current.pid and self._is_pid_running(self._current.pid):
                return self._current
            else:
                self._current.running = False

        saved = self._load_state()
        if saved and saved.running and saved.pid:
            if self._is_pid_running(saved.pid):
                self._current = saved
                return saved

        return ProcessState(running=False)

    def send_signal(self, sig: int):
        """Send a signal to the running process."""
        current = self.status()
        if not current.running or not current.pid:
            raise RuntimeError("sing-box is not running")

        try:
            if sys.platform == "win32":
                if sig == signal.SIGTERM:
                    self.stop()
                else:
                    import ctypes
                    ctypes.windll.kernel32.GenerateConsoleCtrlEvent(sig, current.pid)
            else:
                os.kill(current.pid, sig)
        except Exception as e:
            raise RuntimeError(f"Failed to send signal: {e}")

    def _is_pid_running(self, pid: int | None) -> bool:
        if pid is None:
            return False
        try:
            if sys.platform == "win32":
                import ctypes
                kernel32 = ctypes.windll.kernel32
                handle = kernel32.OpenProcess(0x0400, False, pid)
                if handle:
                    kernel32.CloseHandle(handle)
                    return True
                return False
            else:
                os.kill(pid, 0)
                return True
        except (OSError, ProcessLookupError):
            return False

    def _force_kill(self, pid: int | None):
        """Force kill a process."""
        if pid is None:
            return
        try:
            if sys.platform == "win32":
                subprocess.run(
                    ["taskkill", "/F", "/PID", str(pid)],
                    capture_output=True, timeout=5
                )
            else:
                os.kill(pid, signal.SIGKILL)
        except Exception:
            pass

    def _save_state(self, state: ProcessState):
        """Save process state to disk."""
        self._current = state
        try:
            with open(self.info_path, "w") as f:
                json.dump({
                    "running": state.running,
                    "pid": state.pid,
                    "config_path": state.config_path,
                    "kernel_path": state.kernel_path,
                    "started_at": state.started_at,
                }, f, indent=2)
        except Exception as e:
            logger.warning("Failed to save process state: %s", e)

    def _load_state(self) -> ProcessState | None:
        """Load process state from disk."""
        try:
            if self.info_path.exists():
                with open(self.info_path, "r") as f:
                    data = json.load(f)
                return ProcessState(**data)
        except Exception:
            pass
        return None
