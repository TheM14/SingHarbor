from pathlib import Path

from src import __version__


ROOT = Path(__file__).parent.parent


def test_release_version_and_python_baseline_are_consistent():
    readme = (ROOT / "README.md").read_text("utf-8")
    chinese_readme = (ROOT / "README-ZH.md").read_text("utf-8")
    run_py = (ROOT / "run.py").read_text("utf-8")
    environment = (ROOT / "environment.yml").read_text("utf-8")
    requirements = (ROOT / "requirements.txt").read_text("utf-8")
    theme = (ROOT / "web" / "static" / "css" / "theme.css").read_text("utf-8")
    inbounds_js = (
        ROOT / "web" / "static" / "js" / "inbounds.js"
    ).read_text("utf-8")

    assert __version__ == "1.1.0"
    assert "Version**: v1.1.0" in readme
    assert "版本**：v1.1.0" in chinese_readme
    assert "Python 3.11" not in readme + chinese_readme + run_py
    assert "python=3.12" in readme
    assert "python=3.12" in environment
    assert "python -m pip install -r requirements.txt" in readme
    assert "certbot-dns-cloudflare" in requirements
    assert "certbot-dns-cloudflare" in environment
    dialog_rule = theme.split(".edit-dialog {", 1)[1].split("}", 1)[0]
    assert "margin: auto" in dialog_rule
    assert "inset: 0" in dialog_rule
    assert "revealed.hidden = !revealed.hidden" in inbounds_js
