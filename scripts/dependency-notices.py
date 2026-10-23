"""Regenerate the locked Cargo dependency inventory and accompanying license texts."""
import json
import pathlib
import subprocess
import sys

root = pathlib.Path(__file__).resolve().parent.parent
command = ["cargo", *sys.argv[1:], "metadata", "--locked", "--format-version", "1"]
metadata = json.loads(subprocess.check_output(command, cwd=root))
winapi_source = next((pathlib.Path(p["manifest_path"]).parent for p in metadata["packages"] if p["name"] == "winapi"), None)
destination = root / "notices"
destination.mkdir(exist_ok=True)
lines = [
    "# Third-party notices", "",
    "Generated from Cargo.lock. This inventory does not assign a license to VPN Config Kit.",
    "The project license remains an owner decision. Preserve these notices with distributions.", "",
    "Xray-core is installed separately, is not linked into the Rust executable, and uses MPL-2.0.",
    "Its installer retains the upstream license. Engine release: "
    "[v26.10.21](https://github.com/XTLS/Xray-core/releases/tag/v26.10.21).", "",
    "| Package | Version | Declared license | License texts |",
    "| --- | --- | --- | --- |",
]
for package in sorted(metadata["packages"], key=lambda p: (p["name"], p["version"])):
    if package["id"] in metadata["workspace_members"]:
        continue
    source = pathlib.Path(package["manifest_path"]).parent
    texts = []
    candidates = set()
    for folder in (source, source / "licenses", source / "LICENSES"):
        if folder.is_dir():
            candidates.update(p for p in folder.iterdir() if p.is_file()
                              and (folder != source or p.name.upper().startswith(("LICENSE", "LICENCE", "COPYING", "NOTICE", "UNLICENSE", "AUTHORS"))))
    if package.get("license_file"):
        candidates.add(source / package["license_file"])
    if package["name"].startswith("winapi-") and package["name"].endswith("-windows-gnu") and winapi_source:
        candidates.update((winapi_source / "LICENSE-MIT", winapi_source / "LICENSE-APACHE"))
        header = "\n".join(line for line in (source / "src" / "lib.rs").read_text(encoding="utf-8").splitlines()
                           if line.startswith("//"))
        filename = f"{package['name']}-{package['version']}-NOTICE.txt"
        (destination / filename).write_text(header + "\n", encoding="utf-8", newline="\n")
        texts.append(f"[Source notice](notices/{filename})")
    for path in sorted(candidates):
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8")
        filename = f"{package['name']}-{package['version']}-{path.name}.txt"
        (destination / filename).write_text(text, encoding="utf-8", newline="\n")
        texts.append(f"[{path.name}](notices/{filename})")
    label = package["name"]
    if package.get("repository"):
        label = f"[{label}]({package['repository']})"
    lines.append(f"| {label} | {package['version']} | {package.get('license') or 'See upstream'} | "
                 + (", ".join(texts) if texts else "See upstream package") + " |")
(root / "THIRD_PARTY_NOTICES.md").write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
print(f"Recorded {len(metadata['packages']) - len(metadata['workspace_members'])} dependency packages.")
