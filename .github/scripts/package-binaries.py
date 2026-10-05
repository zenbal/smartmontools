#!/usr/bin/env python3
"""Audit and package native Linux or macOS smartmontools binaries."""

import argparse
import hashlib
import json
import platform
import re
import shutil
import subprocess
import tarfile
import tempfile
from pathlib import Path

SOURCE_URL = "https://github.com/zenbal/smartmontools.git"
LICENSE_SPDX = "GPL-2.0-or-later"


def run(command: list[str]) -> str:
    result = subprocess.run(command, check=True, text=True, capture_output=True)
    return result.stdout + result.stderr


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--source-dir", type=Path, default=Path("."))
    parser.add_argument("--output-dir", type=Path, required=True)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    source = args.source_dir.resolve()
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=True)

    targets = {
        "x86_64-unknown-linux-gnu": ("Linux", "x86_64", "Advanced Micro Devices X86-64"),
        "aarch64-unknown-linux-gnu": ("Linux", "aarch64", "AArch64"),
        "aarch64-apple-darwin": ("Darwin", "arm64", "arm64"),
    }
    try:
        system, expected_arch, expected_machine = targets[args.target]
    except KeyError as error:
        raise SystemExit(f"unsupported target: {args.target}") from error

    actual_system = platform.system()
    actual_arch = platform.machine()
    if (actual_system, actual_arch) != (system, expected_arch):
        raise SystemExit(
            f"{args.target} requires a native {system}/{expected_arch} runner, "
            f"got {actual_system}/{actual_arch}"
        )

    with tempfile.TemporaryDirectory(prefix="smartmontools-package-", dir=output) as temp:
        stage = Path(temp)
        audit = stage / "audit"
        audit.mkdir()
        binaries = {}

        for name in ("smartctl", "smartd"):
            binary = source / name
            version_output = run([str(binary), "--version"])
            (audit / f"{name}-version.txt").write_text(version_output)
            if not version_output.splitlines() or not version_output.splitlines()[0].startswith(
                f"{name} {args.version} "
            ):
                raise SystemExit(
                    f"unexpected {name} version output: {version_output.splitlines()[:1]}"
                )

            file_output = run(["file", str(binary)])
            (audit / f"{name}-file.txt").write_text(file_output)
            dependency_output = ""
            if system == "Darwin":
                architectures = run(["lipo", "-archs", str(binary)]).strip()
                (audit / f"{name}-architectures.txt").write_text(architectures + "\n")
                if architectures != "arm64":
                    raise SystemExit(f"{name} is not an arm64-only executable: {architectures}")
                dependency_output = run(["otool", "-L", str(binary)])
                paths = re.findall(
                    r"^\s+(\S+) \(compatibility version", dependency_output, re.MULTILINE
                )
                if not paths:
                    raise SystemExit(f"otool found no dependencies for {name}")
                for path in paths:
                    if not path.startswith(("/usr/lib/", "/System/Library/")):
                        raise SystemExit(f"non-system macOS dependency for {name}: {path}")
            else:
                elf = run(["readelf", "-h", str(binary)])
                (audit / f"{name}-elf-header.txt").write_text(elf)
                if not re.search(r"Class:\s+ELF64", elf):
                    raise SystemExit(f"{name} is not an ELF64 executable")
                if not re.search(rf"Machine:\s+{re.escape(expected_machine)}\s*$", elf, re.MULTILINE):
                    raise SystemExit(f"{name} has the wrong ELF machine for {args.target}")
                dependency_output = run(["ldd", str(binary)])
                (audit / f"{name}-dependencies.txt").write_text(dependency_output)
                if "not found" in dependency_output:
                    raise SystemExit(f"{name} has an unresolved shared library")
                paths = []
                for line in dependency_output.splitlines():
                    if "=>" in line:
                        dependency = line.split("=>", 1)[1].strip().split()[0]
                        if dependency == "not":
                            raise SystemExit(f"unresolved {name} dependency: {line}")
                        paths.append(dependency)
                    else:
                        match = re.match(r"\s*(/\S+)\s+\(", line)
                        if match:
                            paths.append(match.group(1))
                if not paths:
                    raise SystemExit(f"ldd found no dependencies for {name}")
                for path in paths:
                    if not path.startswith(("/lib/", "/lib64/", "/usr/lib/")):
                        raise SystemExit(f"non-system Linux dependency for {name}: {path}")
                glibc_version = run(["getconf", "GNU_LIBC_VERSION"]).strip()
                (audit / "glibc-version.txt").write_text(glibc_version + "\n")
                symbol_versions = run(["readelf", "--version-info", str(binary)])
                (audit / f"{name}-glibc-symbol-versions.txt").write_text(symbol_versions)
                baseline_match = re.search(r"glibc\s+(\d+(?:\.\d+)+)", glibc_version)
                required_versions = re.findall(r"GLIBC_(\d+(?:\.\d+)+)", symbol_versions)
                if not baseline_match or not required_versions:
                    raise SystemExit(f"could not audit the glibc baseline for {name}")
                baseline = tuple(map(int, baseline_match.group(1).split(".")))
                maximum_required = max(
                    tuple(map(int, version.split("."))) for version in required_versions
                )
                if maximum_required > baseline:
                    raise SystemExit(
                        f"{name} requires GLIBC_{'.'.join(map(str, maximum_required))}, "
                        f"runner provides {baseline_match.group(1)}"
                    )

            (audit / f"{name}-dependencies.txt").write_text(dependency_output)
            binaries[name] = {
                "sha256": sha256(binary),
                "version": version_output.splitlines()[0],
                "audit": f"audit/{name}-dependencies.txt",
            }
            if system == "Linux":
                binaries[name]["maximum_required_glibc"] = ".".join(map(str, maximum_required))
            shutil.copy2(binary, stage / name)

        license_file = source / "COPYING"
        shutil.copy2(license_file, stage / "COPYING")
        manifest = {
            "schema_version": 1,
            "package": "smartmontools",
            "version": args.version,
            "source": {"repository": SOURCE_URL, "commit": args.source_commit},
            "target": args.target,
            "architecture": expected_arch,
            "build_runner": {"system": actual_system, "architecture": actual_arch},
            "glibc_baseline": glibc_version if system == "Linux" else None,
            "binaries": binaries,
            "license": {
                "spdx": LICENSE_SPDX,
                "file": "COPYING",
                "sha256": sha256(license_file),
            },
            "audit_directory": "audit/",
        }
        (stage / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")

        archive_name = f"smartmontools-{args.target}.tar.gz"
        archive_path = output / archive_name
        with tarfile.open(archive_path, "w:gz") as archive:
            for path in sorted(stage.rglob("*")):
                archive.add(path, arcname=path.relative_to(stage).as_posix(), recursive=False)
        archive_hash = sha256(archive_path)
        (output / f"{archive_name}.sha256").write_text(
            f"{archive_hash}  {archive_name}\n"
        )
        print(f"{archive_hash}  {archive_name}")


if __name__ == "__main__":
    main()
