import json
import subprocess
import urllib.request

ADVISORY_URL = "https://security.archlinux.org/issues/all.json"
SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Unknown": 4}

def get_installed_packages():
    """Get a list of installed packages using pacman."""
    result = subprocess.run(["pacman", "-Q"], capture_output=True, text=True)
    packages = {}
    for line in result.stdout.splitlines():
        name, version = line.split()
        packages[name] = version
    return packages

def get_groups():
    """Get a list of package groups using pacman."""
    with urllib.request.urlopen(ADVISORY_URL) as response:
        return json.load(response)

def vercmp(a, b):
    """Compare two version strings."""
    result =subprocess.run(["vercmp", a, b], capture_output=True, text=True)
    return int(result.stdout.strip())

def is_affected(installed_version, group):
    if group["status"] in ("Fixed", "Not affected"):
        return False
    if group["fixed"] is not None:
        return vercmp(installed_version, group["fixed"]) < 0
    return group["status"] == "Vulnerable"

def find_matches(installed, groups):
    """Find installed packages that match the advisory groups."""
    matches = []
    for group in groups:
        for package in group["packages"]:
            if package in installed and is_affected(installed[package], group):
                matches.append({
                    "package": package,
                    "installed": installed[package],
                    "fixed": group["fixed"],
                    "severity": group["severity"],
                    "group": group["name"],
                    "cves": group["issues"],
                })
    return matches

installed = get_installed_packages()
groups = get_groups()
matches = find_matches(installed, groups)
matches.sort(key=lambda m: SEVERITY_ORDER.get(m["severity"], 4))

fixable = [m for m in matches if m["fixed"] is not None]
waiting = [m for m in matches if m["fixed"] is None]

print(f"{len(installed)} packages installed, {len(groups)} vulnerability groups checked.\n")

print(f"Fix available, update these ({len(fixable)}):")
if not fixable:
    print("  none")
for m in fixable:
    print(f'  {m["package"]} {m["installed"]} -> {m["fixed"]}  [{m["severity"]}]  {m["group"]}')

print(f"\nNo fix released yet ({len(waiting)}):")
for m in waiting:
    print(f'  {m["package"]} {m["installed"]}  [{m["severity"]}]  {m["group"]}')