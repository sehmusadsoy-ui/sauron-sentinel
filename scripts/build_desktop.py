"""Build and verify a clean Windows x64 portable folder, ZIP and hash manifest.

Install the pinned desktop and desktop-build extras first. This script performs
no dependency installation and never collects repository or workstation data.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import os
import platform
import shutil
import struct
import subprocess
import sys
import tomllib
import zipfile
from pathlib import Path

from desktop_assets import write_icon

APP_NAME = "SauronSentinel"
PUBLIC_REPOSITORY_URL = "https://github.com/sehmusadsoy-ui/sauron-sentinel"
_FORBIDDEN_SUFFIXES = {
    ".db",
    ".sqlite",
    ".sqlite3",
    ".log",
    ".db-wal",
    ".db-shm",
    ".sqlite-wal",
    ".sqlite-shm",
    ".sqlite3-wal",
    ".sqlite3-shm",
    ".db-journal",
}
_BUILD_DISTRIBUTIONS = (
    "pyinstaller",
    "pyinstaller-hooks-contrib",
    "pywebview",
    "pythonnet",
    "clr_loader",
)
_RUNTIME_DISTRIBUTIONS = (
    "pywebview",
    "pythonnet",
    "clr_loader",
    "cffi",
    "pycparser",
    "proxy_tools",
    "bottle",
    "typing_extensions",
)


def _redirected(path: Path) -> bool:
    return path.is_symlink() or bool(getattr(path, "is_junction", lambda: False)())


def checked_child(path: Path, parent: Path) -> Path:
    """Reject redirections, workspace escapes and recursive operations at the root."""
    resolved, root = path.resolve(), parent.resolve()
    if resolved == root or not resolved.is_relative_to(root):
        raise ValueError(
            "Build target must remain strictly inside its expected workspace directory"
        )
    current = path
    while True:
        if _redirected(current):
            raise ValueError("Build targets cannot be symbolic links or junctions")
        if current == parent or current == current.parent:
            break
        current = current.parent
    return resolved


def dependency_versions() -> dict[str, str]:
    return {name: importlib.metadata.version(name) for name in _BUILD_DISTRIBUTIONS}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _private_needles(private_strings: tuple[str, ...]) -> tuple[bytes, ...]:
    variants = {
        variant.lower()
        for value in private_strings
        if len(value) >= 5
        for variant in (value, value.replace("\\", "/"), value.replace("/", "\\"))
    }
    return tuple(
        pattern
        for value in variants
        for pattern in (value.encode("utf-8"), value.encode("utf-16-le"))
    )


def audit_bundle(bundle: Path, private_strings: tuple[str, ...] = ()) -> list[Path]:
    """Fail rather than publish accidental local data, links or builder paths."""
    files = []
    needles = _private_needles(private_strings)
    for path in sorted(bundle.rglob("*")):
        relative = path.relative_to(bundle)
        if _redirected(path):
            raise ValueError("Portable bundle contains a symbolic link or junction")
        if any(
            part.lower() in {".git", ".venv", "venv", "__pycache__", "screenshots"}
            for part in relative.parts
        ):
            raise ValueError("Portable bundle contains an excluded development directory")
        if not path.is_file():
            continue
        if path.suffix.lower() in _FORBIDDEN_SUFFIXES or path.name.lower().startswith(".env"):
            raise ValueError("Portable bundle contains excluded local data")
        if needles:
            if relative.as_posix() == "README-TR.txt":
                # The intentionally public repository URL can share text with a
                # machine name. Allow that exact reference, not the whole file.
                payload = path.read_bytes().lower()
                for encoding in ("utf-8", "utf-16-le"):
                    payload = payload.replace(PUBLIC_REPOSITORY_URL.encode(encoding), b"")
                if any(needle in payload for needle in needles):
                    raise ValueError("Portable bundle contains a private builder identifier")
                files.append(path)
                continue
            # Keep the scan bounded while retaining overlaps across block boundaries.
            tail = b""
            overlap = max(map(len, needles))
            with path.open("rb") as stream:
                for block in iter(lambda: stream.read(1024 * 1024), b""):
                    payload = (tail + block).lower()
                    if any(needle in payload for needle in needles):
                        raise ValueError("Portable bundle contains a private builder identifier")
                    tail = payload[-overlap:]
        files.append(path)
    return files


def audit_frozen_archives(executable: Path, private_strings: tuple[str, ...]) -> dict[str, int]:
    """Check decompressed Python entries as well as visible portable files."""
    from PyInstaller.archive.readers import CArchiveReader

    needles = _private_needles(private_strings)
    counts = {"frozen_entries": 0, "zip_members": 0}

    def inspect(payload: bytes | None) -> None:
        if payload and any(needle in payload.lower() for needle in needles):
            raise ValueError("Frozen archive contains a private builder identifier")

    archive = CArchiveReader(str(executable))
    for name, entry in archive.toc.items():
        if entry[-1] == "z":
            nested = archive.open_embedded_archive(name)
            for module in nested.toc:
                inspect(nested.extract(module, raw=True))
                counts["frozen_entries"] += 1
        else:
            inspect(archive.extract(name))
            counts["frozen_entries"] += 1
    for path in executable.parent.rglob("*.zip"):
        with zipfile.ZipFile(path) as zipped:
            for name in zipped.namelist():
                inspect(zipped.read(name))
                counts["zip_members"] += 1
    return counts


def archive_bundle(bundle: Path, destination: Path) -> None:
    """Archive only the completed bundle, without source paths or loose data."""
    with zipfile.ZipFile(
        destination, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9
    ) as archive:
        for path in audit_bundle(bundle):
            archive.write(path, (Path(bundle.name) / path.relative_to(bundle)).as_posix())


def copy_notices(repository: Path, bundle: Path) -> None:
    shutil.copyfile(repository / "LICENSE", bundle / "LICENSE.txt")
    notices = [
        "Sauron Sentinel 0.4.0 - third-party components",
        "",
        "Python and the bundled libraries retain their respective licenses.",
        "Available license texts are included under third-party-licenses.",
        "Microsoft Edge WebView2 Runtime is supplied by the target Windows system; it is not bundled.",
        "",
    ]
    licenses = bundle / "third-party-licenses"
    for name in _RUNTIME_DISTRIBUTIONS:
        try:
            distribution = importlib.metadata.distribution(name)
        except importlib.metadata.PackageNotFoundError:
            continue
        notices.append(f"{distribution.metadata['Name']} {distribution.version}")
        for item in distribution.files or []:
            if not any(part.endswith(".dist-info") for part in item.parts):
                continue
            if not item.name.upper().startswith(("LICENSE", "COPYING", "NOTICE")):
                continue
            source = Path(distribution.locate_file(item))
            if source.is_file():
                target = licenses / name / item.name
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, target)
    python_license = Path(sys.base_prefix) / "LICENSE.txt"
    if python_license.is_file():
        target = licenses / "Python" / "LICENSE.txt"
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(python_license, target)
    (bundle / "THIRD-PARTY-NOTICES.txt").write_text("\n".join(notices) + "\n", encoding="utf-8")
    (bundle / "README-TR.txt").write_text(
        "SAURON SENTINEL 0.4.0\n\n"
        "1. ZIP dosyasının tamamını bir klasöre çıkar.\n"
        "2. SauronSentinel.exe dosyasını çift tıklayarak aç.\n"
        "3. İlk açılışta kaynakların erişim durumuna ve son kontrol zamanına bak.\n"
        "   Erişilebilir bir kaynak, bilgisayarın güvenli olduğunu kanıtlamaz.\n"
        "4. Bir alarmı açıp kanıtını, açıklamasını ve güvenli kontrol önerilerini incele.\n"
        "   İstersen İncelendi veya Beklenen olarak işaretle ve kısa bir not ekle.\n"
        "   Alarm olmaması veya kaynakta seçili olay bulunmaması geçerli bir sonuçtur.\n"
        "5. Bildirimler başlangıçta kapalıdır. Ayarlardan açabilir, en düşük önem\n"
        "   düzeyini ve kontrol aralığını seçebilirsin. Deneme bildirimi alarm değildir.\n"
        "   Windows bildirimleri gizleyebilir; bildirim kuyruğu teslim kanıtı değildir.\n"
        "6. Pencereyi kapattığında izleme ve bildirimler durur.\n\n"
        "_internal klasörünü EXE dosyasının yanında tut. Python kurmak gerekmez.\n"
        "Gereksinimler: Windows 10/11 x64, .NET Framework ve Microsoft Edge WebView2 Runtime.\n"
        "WebView2 eksikse resmi Microsoft WebView2 Runtime yükleyicisini kullan.\n"
        "Program normal kullanıcı olarak açılır; yönetici izni veya otomatik başlatma ayarı yapmaz.\n"
        "Security günlüğü için ek izin gerekebilir; erişim durumu panelde gösterilir.\n"
        "Eksik, erişilemeyen, sınıra ulaşan veya güncel olmayan kaynakları ayrıca kontrol et.\n"
        "Başlangıçta eski kayıtlar incelenir; bunlar yeni Windows bildirimi oluşturmaz.\n"
        "Veriler kullanıcıya ait LocalAppData/SauronSentinel alanında saklanır.\n"
        "Notlar, inceleme durumları ve ayarlar bu bilgisayarda saklanır.\n"
        "Dışa aktarmadan önce dosyadaki kişisel bilgileri gözden geçir.\n"
        "Bu paket gerçek günlük, kullanıcı verisi veya önceden doldurulmuş alarm içermez.\n"
        "RF Canvas, CSI Radar ve LabMate bağlantıları yalnızca planlanmıştır.\n"
        "Bu araç seçili Windows kayıtlarını inceler; tüm güvenlik olaylarını kapsamaz.\n\n"
        "Kaynak kod: https://github.com/sehmusadsoy-ui/sauron-sentinel\n",
        encoding="utf-8",
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--prepare-icon", action="store_true", help="Generate the original icon without building"
    )
    args = parser.parse_args(argv)
    repository = Path(__file__).resolve().parents[1]
    icon = repository / "packaging" / "sentinel.ico"
    if args.prepare_icon:
        write_icon(icon)
        print("Generated packaging/sentinel.ico")
        return 0
    if (
        sys.platform != "win32"
        or struct.calcsize("P") != 8
        or platform.machine().upper() not in {"AMD64", "X86_64"}
    ):
        parser.error("Build on Windows x64 using a 64-bit Python interpreter")
    try:
        versions = dependency_versions()
    except importlib.metadata.PackageNotFoundError:
        parser.error("Install the pinned desktop and desktop-build extras before building")
    with (repository / "pyproject.toml").open("rb") as stream:
        version = tomllib.load(stream)["project"]["version"]
    if version != "0.4.0":
        parser.error(
            "Update packaging/version_info.txt and the portable notes before changing the release version"
        )
    workspace = repository.parent
    build = checked_child(workspace / "work" / f"desktop-build-{version}", workspace / "work")
    output = checked_child(
        workspace / "outputs" / f"Sauron-Sentinel-{version}-Windows-x64", workspace / "outputs"
    )
    bundle = checked_child(output / APP_NAME, output)
    build.mkdir(parents=True, exist_ok=True)
    output.mkdir(parents=True, exist_ok=True)
    pyinstaller_work = checked_child(build / "pyinstaller", build)
    write_icon(icon)
    command = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--noconfirm",
        "--workpath",
        str(pyinstaller_work),
        "--distpath",
        str(output),
        str(repository / "packaging" / "SauronSentinel.spec"),
    ]
    environment = os.environ.copy()
    environment["PYINSTALLER_CONFIG_DIR"] = str(checked_child(build / "cache", build))
    with (build / "pyinstaller.log").open("w", encoding="utf-8") as log:
        subprocess.run(
            command,
            cwd=repository,
            env=environment,
            check=True,
            stdout=log,
            stderr=subprocess.STDOUT,
        )
    executable = bundle / f"{APP_NAME}.exe"
    if not executable.is_file():
        raise RuntimeError("PyInstaller did not produce the expected executable")
    report = build / "diagnostics.json"
    report.unlink(missing_ok=True)
    subprocess.run([str(executable), "--diagnose", str(report)], cwd=build, check=True, timeout=90)
    diagnostics = json.loads(report.read_text(encoding="utf-8"))
    if (
        diagnostics.get("status") != "ok"
        or diagnostics.get("frozen") is not True
        or diagnostics.get("version") != version
    ):
        raise RuntimeError("Packaged executable self-check failed")
    copy_notices(repository, bundle)
    private_strings = tuple(
        value
        for value in (str(workspace), str(Path.home()), os.environ.get("COMPUTERNAME", ""))
        if value
    )
    files = audit_bundle(bundle, private_strings)
    archive_audit = audit_frozen_archives(executable, private_strings)
    package_name = f"Sauron-Sentinel-{version}-Windows-x64.zip"
    archive = checked_child(output.parent / package_name, output.parent)
    archive_bundle(bundle, archive)
    manifest = {
        "schema_version": 1,
        "product": "Sauron Sentinel",
        "version": version,
        "platform": "Windows-x64",
        "python": platform.python_version(),
        "dependencies": versions,
        "diagnostics": diagnostics,
        "privacy_audit": {"files": len(files), **archive_audit},
        "archive": {
            "name": archive.name,
            "bytes": archive.stat().st_size,
            "sha256": sha256(archive),
        },
        "files": [
            {
                "path": (Path(APP_NAME) / path.relative_to(bundle)).as_posix(),
                "bytes": path.stat().st_size,
                "sha256": sha256(path),
            }
            for path in files
        ],
    }
    (output / "build-manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (output / "SHA256SUMS.txt").write_text(f"{sha256(archive)}  {archive.name}\n", encoding="ascii")
    print(
        json.dumps(
            {"archive": archive.name, "version": version, "files": len(files), "diagnostics": "ok"},
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
