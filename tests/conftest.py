import os
import sys
from pathlib import Path

import matplotlib
matplotlib.use("Agg")  # headless: avoid plt.show() blocking and no-display errors

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]

# so `import cli`, `from rules...`, etc. work the same way the modules'
# own sys.path.append(...) hacks assume when invoked as scripts.
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


@pytest.fixture
def repo_root():
    return REPO_ROOT


@pytest.fixture
def isolated_cwd(tmp_path, monkeypatch):
    """Run a test with cwd = a scratch directory that symlinks the repo's
    read-only trained models in, so any hardcoded relative paths like
    "output/x.pcap" or "dataset/<protocol>/..." land in tmp_path instead of
    polluting the real repository.
    """
    (tmp_path / "models").symlink_to(REPO_ROOT / "models")
    (tmp_path / "output").mkdir()
    (tmp_path / "dataset").mkdir()
    monkeypatch.chdir(tmp_path)
    return tmp_path


@pytest.fixture
def isolated_cwd_no_models(tmp_path, monkeypatch):
    """Like isolated_cwd, but deliberately does NOT symlink models/ or create
    dataset/ -- proves the declarative generation path (protocols/*.yaml)
    needs neither. protocols/ and scenarios/ still resolve correctly because
    their loaders locate themselves via __file__, not cwd.
    """
    (tmp_path / "output").mkdir()
    monkeypatch.chdir(tmp_path)
    return tmp_path


@pytest.fixture
def sample_pcap():
    def _get(protocol):
        return str(REPO_ROOT / "data" / f"{protocol}_pcap.pcap")
    return _get
