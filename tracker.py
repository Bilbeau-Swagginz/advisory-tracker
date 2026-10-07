import json
import re
import subprocess
import urllib.request

ADVISORY_URL = "https://security.archlinux.org/issues/all.json"
SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Unknown": 4}

# Verify against each kernel's PKGBUILD: which arch kernel
# package's advisories apply to each CachyOS kernel variant.
KERNEL_MAP = {
    "linux-cachyos": "linux",
    "linux-cachyos-bore": "linux",
    "linux-cachyos-bmq": "linux",
    "linux-cachyos-deckify": "linux",
    "linux-cachyos-eevdf": "linux",
    "linux-cachyos-lts": "linux-lts",
    "linux-cachyos-hardened": "linux-hardened",
    "linux-cachyos-server": "linux",
    "linux-cachyos-rt-bore": "linux",
}

DISTRO_SUFFIX = re.compile(r"\.(arch|hardened)\d+")


def get_installed_packages():
    """Get a list of installed packages using pacman."""
    result = subprocess.run(
        ["pacman", "-Q"], capture_output=True, text=True, check=True
    )
    packages = {}
    for line in result.stdout.splitlines():
        name, version = line.split()
        packages[name] = version
    return packages


def get_groups():
    """Get a list of package groups using Arch Security Tracker."""
    with urllib.request.urlopen(ADVISORY_URL, timeout=30) as response:
        return json.load(response)


def vercmp(a, b):
    """Compare two version strings."""
    result = subprocess.run(
        ["vercmp", a, b], capture_output=True, text=True, check=True
    )
    return int(result.stdout.strip())


def to_tracker_name(package):
    """Translate package name to the name Arch Security Tracker uses."""
    return KERNEL_MAP.get(package, package)


def upstream_version(version):
    """Drop distro tag and pkgrel"""
    return DISTRO_SUFFIX.sub("", version).rsplit("-", 1)[0]


def index_tracker_by_name(installed):
    """Group installed packages under name tracker knows them by."""
    index = {}
    for name, version in installed.items():
        index.setdefault(to_tracker_name(name), []).append((name, version))
    return index


def is_affected(installed_version, group, kernel=False):
    """Decide whether installed version is affected by advisory group."""
    if group["status"] == "Not affected":
        return False
    if group["fixed"] is not None:
        if kernel:
            return (
                vercmp(
                    upstream_version(installed_version),
                    upstream_version(group["fixed"]),
                )
                < 0
            )
        return vercmp(installed_version, group["fixed"]) < 0
    return group["status"] == "Vulnerable"


def find_matches(installed, groups):
    """Find installed packages that match the advisory groups."""
    index = index_tracker_by_name(installed)
    matches = []
    for group in groups:
        for tracker_name in group["packages"]:
            for pkg_name, version in index.get(tracker_name, []):
                if is_affected(version, group, kernel=pkg_name in KERNEL_MAP):
                    matches.append(
                        {
                            "package": pkg_name,
                            "installed": version,
                            "fixed": group["fixed"],
                            "severity": group["severity"],
                            "group": group["name"],
                            "cves": group["issues"],
                        }
                    )
    return matches


def main():
    installed = get_installed_packages()
    groups = get_groups()
    matches = find_matches(installed, groups)
    matches.sort(key=lambda m: SEVERITY_ORDER.get(m["severity"], 4))

    fixable = [m for m in matches if m["fixed"] is not None]
    waiting = [m for m in matches if m["fixed"] is None]

    print(
        f"{len(installed)} packages installed, {len(groups)} vulnerability groups checked.\n"
    )

    print(f"Fix available, update these ({len(fixable)}):")
    if not fixable:
        print("  none")
    for m in fixable:
        print(
            f"  {m['package']} {m['installed']} -> {m['fixed']}  [{m['severity']}]  {m['group']}"
        )

    print(f"\nNo fix released yet ({len(waiting)}):")
    for m in waiting:
        print(f"  {m['package']} {m['installed']}  [{m['severity']}]  {m['group']}")


if __name__ == "__main__":
    main()
