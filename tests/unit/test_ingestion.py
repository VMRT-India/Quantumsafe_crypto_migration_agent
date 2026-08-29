"""
tests/unit/test_ingestion.py
Unit tests for the Ingestion module (T-02).
"""

from __future__ import annotations

from pathlib import Path

from qsma.ingestion.walker import _detect_language, _is_binary, collect_snapshot
from qsma.utils.models import IngestionConfig

# ---------------------------------------------------------------------------
# _detect_language
# ---------------------------------------------------------------------------


class TestDetectLanguage:
    def test_python(self) -> None:
        assert _detect_language(Path("foo.py")) == "python"

    def test_java(self) -> None:
        assert _detect_language(Path("Foo.java")) == "java"

    def test_go(self) -> None:
        assert _detect_language(Path("main.go")) == "go"

    def test_c(self) -> None:
        assert _detect_language(Path("lib.c")) == "c"

    def test_c_header(self) -> None:
        assert _detect_language(Path("lib.h")) == "c"

    def test_rust(self) -> None:
        assert _detect_language(Path("main.rs")) == "rust"

    def test_unknown(self) -> None:
        assert _detect_language(Path("data.json")) == "unknown"

    def test_case_insensitive(self) -> None:
        assert _detect_language(Path("Foo.PY")) == "python"


# ---------------------------------------------------------------------------
# _is_binary
# ---------------------------------------------------------------------------


class TestIsBinary:
    def test_text_is_not_binary(self) -> None:
        assert _is_binary(b"hello world\nsome code here") is False

    def test_nul_byte_is_binary(self) -> None:
        assert _is_binary(b"some\x00bytes") is True

    def test_empty_is_not_binary(self) -> None:
        assert _is_binary(b"") is False


# ---------------------------------------------------------------------------
# collect_snapshot
# ---------------------------------------------------------------------------


class TestCollectSnapshot:
    def test_single_python_file(self, tmp_path: Path) -> None:
        f = tmp_path / "hello.py"
        f.write_text("print('hello')", encoding="utf-8")
        snap = collect_snapshot(tmp_path)
        assert snap.file_count == 1
        assert snap.files[0].language == "python"
        assert snap.files[0].content == "print('hello')"

    def test_non_matching_extension_excluded(self, tmp_path: Path) -> None:
        (tmp_path / "README.md").write_text("# readme", encoding="utf-8")
        snap = collect_snapshot(tmp_path)
        assert snap.file_count == 0

    def test_multiple_extensions(self, tmp_path: Path) -> None:
        (tmp_path / "app.py").write_text("x = 1", encoding="utf-8")
        (tmp_path / "Main.java").write_text("class Main {}", encoding="utf-8")
        config = IngestionConfig(extensions=[".py", ".java"])
        snap = collect_snapshot(tmp_path, config)
        assert snap.file_count == 2
        langs = {f.language for f in snap.files}
        assert langs == {"python", "java"}

    def test_oversized_file_excluded(self, tmp_path: Path) -> None:
        f = tmp_path / "big.py"
        f.write_text("x = 1" * 100_000, encoding="utf-8")
        config = IngestionConfig(max_file_size=100)
        snap = collect_snapshot(tmp_path, config)
        assert snap.file_count == 0

    def test_binary_file_excluded(self, tmp_path: Path) -> None:
        f = tmp_path / "binary.py"
        f.write_bytes(b"\x00\x01\x02\x03some binary data")
        snap = collect_snapshot(tmp_path)
        assert snap.file_count == 0

    def test_exclude_venv(self, tmp_path: Path) -> None:
        venv = tmp_path / ".venv" / "lib"
        venv.mkdir(parents=True)
        (venv / "some.py").write_text("x = 1", encoding="utf-8")
        (tmp_path / "app.py").write_text("y = 2", encoding="utf-8")
        snap = collect_snapshot(tmp_path)
        assert snap.file_count == 1
        assert snap.files[0].path.name == "app.py"

    def test_exclude_pycache(self, tmp_path: Path) -> None:
        cache = tmp_path / "__pycache__"
        cache.mkdir()
        (cache / "module.cpython-311.pyc").write_bytes(b"x = 1")  # not a .py file anyway
        (tmp_path / "module.py").write_text("x = 1", encoding="utf-8")
        snap = collect_snapshot(tmp_path)
        assert snap.file_count == 1

    def test_respects_gitignore(self, tmp_path: Path) -> None:
        (tmp_path / ".gitignore").write_text("ignored/\n", encoding="utf-8")
        ignored_dir = tmp_path / "ignored"
        ignored_dir.mkdir()
        (ignored_dir / "secret.py").write_text("password = 'x'", encoding="utf-8")
        (tmp_path / "main.py").write_text("print('hi')", encoding="utf-8")
        snap = collect_snapshot(tmp_path)
        names = [f.path.name for f in snap.files]
        assert "secret.py" not in names
        assert "main.py" in names

    def test_deterministic_ordering(self, tmp_path: Path) -> None:
        for name in ["z.py", "a.py", "m.py"]:
            (tmp_path / name).write_text("x=1", encoding="utf-8")
        snap = collect_snapshot(tmp_path)
        names = [f.path.name for f in snap.files]
        assert names == sorted(names)

    def test_single_file_mode(self, tmp_path: Path) -> None:
        f = tmp_path / "only.py"
        f.write_text("x = 42", encoding="utf-8")
        snap = collect_snapshot(f)
        assert snap.file_count == 1
        assert snap.files[0].content == "x = 42"

    def test_root_path_recorded(self, tmp_path: Path) -> None:
        (tmp_path / "app.py").write_text("x=1", encoding="utf-8")
        snap = collect_snapshot(tmp_path)
        assert snap.root_path == tmp_path.resolve()

    def test_recursive_walk(self, tmp_path: Path) -> None:
        sub = tmp_path / "pkg" / "sub"
        sub.mkdir(parents=True)
        (sub / "deep.py").write_text("y=2", encoding="utf-8")
        (tmp_path / "top.py").write_text("x=1", encoding="utf-8")
        snap = collect_snapshot(tmp_path)
        assert snap.file_count == 2

    def test_fixtures_rsa(self) -> None:
        """Smoke test against the real RSA fixture project."""
        fixture = Path(__file__).parent.parent / "fixtures" / "sample_projects" / "python_rsa"
        snap = collect_snapshot(fixture)
        assert snap.file_count >= 1
        assert all(f.language == "python" for f in snap.files)

    def test_size_bytes_recorded(self, tmp_path: Path) -> None:
        content = "x = 1\n"
        f = tmp_path / "code.py"
        f.write_text(content, encoding="utf-8")
        snap = collect_snapshot(tmp_path)
        assert snap.files[0].size_bytes == len(content.encode("utf-8"))
