# advisory-tracker

Checks the packages installed on your **CachyOS** (or other Arch-based) machine against the [Arch Security Tracker](https://security.archlinux.org/) and tells you which ones need updating, sorted by severity.

It maps CachyOS kernel variants (`linux-cachyos`, `-lts`, `-bore`, `-hardened`, ...) to the Arch kernel advisories that apply to them, since the Arch tracker doesn't know those package names.

## Status

Early but working. Reports installed packages affected by an advisory, split into "fix available" and "no fix released yet". See [Limitations](#limitations) before relying on it.

## Usage

```bash
git clone https://github.com/Bilbeau-Swagginz/advisory-tracker.git
cd advisory-tracker
python tracker.py
```

**Requirements:** Python 3, `pacman` (which provides `vercmp`), and internet access.

The tool is read-only. It runs `pacman -Q` and `vercmp`, makes one HTTPS request to `security.archlinux.org`, and prints a report. It changes nothing on your system.

## Example output

```
1585 packages installed, 2444 vulnerability groups checked.

Fix available, update these (0):
  none

No fix released yet (1):
  lua51 5.1.5-13.1  [Low]  AVG-1302

Old tracker entries, verify manually (22):
  pam 1.7.3-1.1  [High]  AVG-2901  (tracker last recorded: 1.7.0-2) https://security.archlinux.org/AVG-2901
  ...

Coverage: 1531 checked, 48 CachyOS-only, 6 foreign/AUR (not checked)
```

## How it works

1. Lists installed packages with `pacman -Q`.
2. Downloads advisory feed from the Arch Security Tracker.
3. Translates CachyOS kernel names to the Arch names the tracker uses.
4. Compares versions with pacman's own `vercmp` and reports affected packages, sorted by severity.
5. Separates stale tracker records ( the tracker only ever recorded upstream version) into "verify manually" section instead of hiding them.
6. Reports which installed packages the tracker cannot speak for (CachyOS-only and AUR/foreign), so absence from findings is not mistaken for "safe".

## How is this different from arch-audit?

[arch-audit](https://gitlab.archlinux.org/archlinux/arch-audit) is the established tool for this job on Arch. This project is aimed at CachyOS specifically, starting with the kernel mapping, and is also a learning project built in the open. If you run plain Arch, arch-audit is the more better choice.

## Limitations

- **Coverage is limited to packages in the Arch Security Tracker.** CachyOS-only and AUR/foreign packages are listed in summary but are **not checked**, including Electron-based apps and Wine/Proton builds.
- **The kernel mapping is an assumption.** Each CachyOS variant is assumed to track the matching Arch kernel. Release-candidate kernels are not mapped.
- **The stale heuristic is a guess, not proof.** An entry is flagged when upstream version is newer than version the tracker last recorded as affected. Always open linked tracker page before dismissing one.
- **Does not check if your running kernel matches the installed one**

## Roadmap

- [x] Read installed packages
- [x] Fetch advisory data from the Arch Security Tracker
- [x] Match installed versions against advisories
- [x] Sort results by severity
- [x] CachyOS kernel mapping
- [x] Unit tests
- [x] Coverage report (checked / CachyOS-only / foreign)
- [ ] "Reboot needed" check for kernel updates
- [ ] Second data source for packages the Arch tracker doesn't cover
- [ ] Scheduled weekly runs
- [ ] Alerts for critical advisories

## Contributing

Issues and pull requests welcome. Reports from other CachyOS setups are especially useful: different kernel variants, and the v3, v4, and znver4 repos.

## License

[MIT](LICENSE)
