import json
import re
import subprocess
import urllib.request

ADVISORY_URL = "https://security.archlinux.org/issues/all.json"
SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Unknown": 4}
TRACKER_URL = "https://security.archlinux.org"


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
ARCH_REPOS = {"core", "extra", "multilib"}


def get_installed_packages():
    """Return {package_name: version} for all installed packages."""
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


def get_repo_map():
    """Return {package_name: repos offering it} from pacman's sync databases."""
    result = subprocess.run(
        ["pacman", "-Sl"], capture_output=True, text=True, check=True
    )
    repos = {}
    for line in result.stdout.splitlines():
        repo, name, *_ = line.split(maxsplit=2)
        repos.setdefault(name, set()).add(repo)
    return repos


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
    """Remove distro tag and pkgrel: 6.17.2.arch1-1 -> 6.17.2"""
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


def looks_stale(installed_version, group):
    """True if tracker only ever recorded older upstream version as affected."""
    affected = group.get("affected")
    if group["fixed"] is not None or not affected:
        return False
    return vercmp(upstream_version(installed_version), upstream_version(affected)) > 0


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
                            "affected": group.get("affected"),
                            "stale": looks_stale(version, group),
                        }
                    )
    return matches


def classify_package(name, repos):
    """Explain how well the Arch tracker can speak for one installed package."""
    if name in KERNEL_MAP:
        return "mapped"
    offered_by = repos.get(name, set())
    if offered_by & ARCH_REPOS:
        return "covered"
    if any(repo.startswith("cachyos") for repo in offered_by):
        return "cachyos_only"
    return "foreign"


def coverage_buckets(installed, repos):
    """Sort installed package names into coverage buckets."""
    buckets = {"covered": [], "mapped": [], "cachyos_only": [], "foreign": []}
    for name in installed:
        buckets[classify_package(name, repos)].append(name)
    return buckets


def clean(text):
    """Drop control characters (including ANSI escape characters)from text before printing."""
    return "".join(ch for ch in str(text) if ch.isprintable())


def format_match(m):
    """Render one finding as single report line."""
    version = f"{m['installed']} -> {m['fixed']}" if m["fixed"] else m["installed"]
    line = f"  {m['package']} {version}  [{m['severity']}]  {m['group']}"
    if m["stale"]:
        line += f"  (tracker last recorded: {m['affected']}) {TRACKER_URL}/{m['group']}"
    return clean(line)


def print_section(title, rows):
    print(f"\n{title} ({len(rows)}):")
    if not rows:
        print("  none")
    for m in rows:
        print(format_match(m))


def main():
    installed = get_installed_packages()
    groups = get_groups()
    matches = find_matches(installed, groups)
    matches.sort(key=lambda m: SEVERITY_ORDER.get(m["severity"], 4))

    fixable = [m for m in matches if m["fixed"] is not None]
    waiting = [m for m in matches if m["fixed"] is None and not m["stale"]]
    stale = [m for m in matches if m["fixed"] is None and m["stale"]]

    print(
        f"{len(installed)} packages installed, "
        f"{len(groups)} vulnerability groups checked."
    )
    print_section("Fix available, update these", fixable)
    print_section("No fix released yet", waiting)
    print_section("Old tracker entries, verify manually", stale)

    repos = get_repo_map()
    buckets = coverage_buckets(installed, repos)
    checked = len(buckets["covered"]) + len(buckets["mapped"])
    print(
        f"\nCoverage: {checked} checked, "
        f"{len(buckets['cachyos_only'])} CachyOS-only, "
        f"{len(buckets['foreign'])} foreign/AUR (not checked)"
    )
    for label in ("cachyos_only", "foreign"):
        names = ", ".join(clean(n) for n in sorted(buckets[label]))
        print(f"  {label}: {names or 'none'}")

if __name__ == "__main__":
    main()