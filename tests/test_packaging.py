"""Portable packaging must not collect local data or escape its build targets."""

import importlib.util
import io
import stat
import struct
import sys
import tomllib
import zipfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from sauron_sentinel import __version__

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"


def _script(name):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def builder(monkeypatch):
    monkeypatch.syspath_prepend(str(SCRIPTS))
    return _script("build_desktop")


def test_release_versions_match_runtime_resources_and_portable_notes(builder, tmp_path):
    repository = SCRIPTS.parent
    metadata = tomllib.loads((repository / "pyproject.toml").read_text(encoding="utf-8"))
    assert metadata["project"]["version"] == __version__ == builder.RELEASE_VERSION == "0.4.1"
    resource = (repository / "packaging" / "version_info.txt").read_text(encoding="utf-8")
    numeric_version = tuple(int(part) for part in __version__.split(".")) + (0,)
    assert f"filevers={numeric_version}" in resource
    assert f"prodvers={numeric_version}" in resource
    assert f"StringStruct('FileVersion', '{__version__}')" in resource
    assert f"StringStruct('ProductVersion', '{__version__}')" in resource
    builder.copy_notices(repository, tmp_path)
    assert f"SAURON SENTINEL {__version__}" in (tmp_path / "README-TR.txt").read_text(
        encoding="utf-8"
    )
    assert f"Sauron Sentinel {__version__} - third-party components" in (
        tmp_path / "THIRD-PARTY-NOTICES.txt"
    ).read_text(encoding="utf-8")


def test_icon_is_a_complete_multiresolution_windows_icon():
    icon = _script("desktop_assets").icon_bytes((16, 32, 256))
    assert struct.unpack_from("<HHH", icon) == (0, 1, 3)
    for index, expected_size in enumerate((16, 32, 256)):
        width, height, _, _, planes, bits, length, offset = struct.unpack_from(
            "<BBBBHHII", icon, 6 + index * 16
        )
        assert (width or 256, height or 256, planes, bits) == (expected_size, expected_size, 1, 32)
        payload = icon[offset : offset + length]
        assert payload.startswith(b"\x89PNG\r\n\x1a\n")
        assert struct.unpack_from(">II", payload, 16) == (expected_size, expected_size)
        assert payload.endswith(b"IEND\xaeB`\x82")


@pytest.mark.parametrize(
    "suffix", [".db", ".sqlite", ".sqlite3", ".log", ".db-wal", ".sqlite3-shm"]
)
def test_local_data_cannot_enter_portable_bundle(builder, tmp_path, suffix):
    (tmp_path / ("private" + suffix)).write_bytes(b"sensitive")
    with pytest.raises(ValueError, match="excluded local data"):
        builder.audit_bundle(tmp_path)


def test_bundle_rejects_private_paths_even_across_scan_blocks(builder, tmp_path):
    private = "C:/private-workstation/user-profile"
    (tmp_path / "application.bin").write_bytes(b"a" * (1024 * 1024 - 5) + private.encode())
    with pytest.raises(ValueError, match="private builder"):
        builder.audit_bundle(tmp_path, (private,))


def test_bundle_rejects_utf16_private_identifiers(builder, tmp_path):
    (tmp_path / "application.bin").write_bytes("C:/private-user/profile".encode("utf-16-le"))
    with pytest.raises(ValueError, match="private builder"):
        builder.audit_bundle(tmp_path, ("C:/private-user/profile",))


def test_bundle_scans_both_windows_path_separator_forms(builder, tmp_path):
    (tmp_path / "application.bin").write_bytes(b"C:/private-user/profile")
    with pytest.raises(ValueError, match="private builder"):
        builder.audit_bundle(tmp_path, (r"C:\private-user\profile",))


def test_public_repository_reference_does_not_mask_other_private_text(builder, tmp_path):
    readme = tmp_path / "README-TR.txt"
    readme.write_text(builder.PUBLIC_REPOSITORY_URL, encoding="utf-8")
    assert builder.audit_bundle(tmp_path, ("github",)) == [readme]
    readme.write_text(builder.PUBLIC_REPOSITORY_URL + "\nComputer: github", encoding="utf-8")
    with pytest.raises(ValueError, match="private builder"):
        builder.audit_bundle(tmp_path, ("github",))
    readme.write_text(builder.PUBLIC_REPOSITORY_URL, encoding="utf-8")
    (tmp_path / "application.bin").write_bytes(b"github")
    with pytest.raises(ValueError, match="private builder"):
        builder.audit_bundle(tmp_path, ("github",))


def test_archive_contains_only_the_named_portable_folder(builder, tmp_path):
    bundle = tmp_path / "SauronSentinel"
    bundle.mkdir()
    (bundle / "SauronSentinel.exe").write_bytes(b"app")
    (bundle / "README-TR.txt").write_bytes(b"readme")
    (tmp_path / "private.db").write_bytes(b"not part of bundle")
    archive = tmp_path / "portable.zip"
    builder.archive_bundle(bundle, archive)
    with zipfile.ZipFile(archive) as reader:
        assert set(reader.namelist()) == {
            "SauronSentinel/SauronSentinel.exe",
            "SauronSentinel/README-TR.txt",
        }


def _archive_with_library_zip(member, payload):
    zipped = io.BytesIO()
    with zipfile.ZipFile(zipped, "w", compression=zipfile.ZIP_DEFLATED) as library:
        library.writestr(member, payload)
    entries = {"base_library.zip": zipped.getvalue()}
    return SimpleNamespace(toc={"base_library.zip": ("x",)}, extract=entries.__getitem__)


def test_frozen_audit_checks_decompressed_library_zip(builder):
    private = "C:/private-builder/profile"
    clean = _archive_with_library_zip("encodings/__init__.pyc", b"bytecode")
    assert builder._audit_frozen_entries(clean, (private,)) == {
        "frozen_entries": 1,
        "zip_members": 1,
    }
    embedded = _archive_with_library_zip("encodings/__init__.pyc", private.encode("utf-16-le"))
    assert private.encode("utf-16-le") not in embedded.extract("base_library.zip")
    with pytest.raises(ValueError, match="private builder"):
        builder._audit_frozen_entries(embedded, (private,))


@pytest.mark.parametrize(
    "name", ["../private.pyc", r"data\..\private.pyc", "file.pyc:stream", "NUL.pyc"]
)
def test_frozen_audit_rejects_unsafe_archive_paths(builder, name):
    embedded = _archive_with_library_zip(name, b"bytecode")
    with pytest.raises(ValueError, match="unsafe Windows path"):
        builder._audit_frozen_entries(embedded, ())


def test_frozen_audit_rejects_private_names_and_links(builder):
    private = "private-builder"
    embedded = _archive_with_library_zip(f"{private}/example.pyc", b"bytecode")
    with pytest.raises(ValueError, match="private builder"):
        builder._audit_frozen_entries(embedded, (private,))
    symlink = zipfile.ZipInfo("encodings/link.pyc")
    symlink.external_attr = stat.S_IFLNK << 16
    with pytest.raises(ValueError, match="link or reparse point"):
        builder._audit_frozen_entries(_archive_with_library_zip(symlink, b"target"), ())
    reparse = zipfile.ZipInfo("encodings/link.pyc")
    reparse.external_attr = stat.FILE_ATTRIBUTE_REPARSE_POINT
    with pytest.raises(ValueError, match="link or reparse point"):
        builder._audit_frozen_entries(_archive_with_library_zip(reparse, b"target"), ())
    carchive_symlink = SimpleNamespace(toc={"runtime/link.dll": ("n",)})
    with pytest.raises(ValueError, match="link or reparse point"):
        builder._audit_frozen_entries(carchive_symlink, ())


def test_build_target_must_be_strict_child(builder, tmp_path):
    assert builder.checked_child(tmp_path / "build", tmp_path) == tmp_path / "build"
    for candidate in (tmp_path, tmp_path / ".." / "elsewhere"):
        with pytest.raises(ValueError, match="strictly inside"):
            builder.checked_child(candidate, tmp_path)


def test_build_target_rejects_linked_parent(builder, tmp_path):
    actual = tmp_path / "actual"
    actual.mkdir()
    linked = tmp_path / "linked"
    try:
        linked.symlink_to(actual, target_is_directory=True)
    except OSError:
        pytest.skip("Creating directory symlinks is unavailable on this workstation")
    with pytest.raises(ValueError, match="symbolic links"):
        builder.checked_child(linked / "build", linked)


def test_icon_preparation_does_not_require_build_dependencies(builder, monkeypatch, tmp_path):
    repository = tmp_path / "repository"
    (repository / "packaging").mkdir(parents=True)
    (repository / "scripts").mkdir()
    monkeypatch.setattr(builder, "__file__", str(repository / "scripts" / "build_desktop.py"))
    monkeypatch.setattr(sys, "platform", "not-windows")
    assert builder.main(["--prepare-icon"]) == 0
    assert (repository / "packaging" / "sentinel.ico").read_bytes().startswith(b"\0\0\1\0")
