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

No fix released yet (23):
  pam 1.7.3-1.1  [High]  AVG-2901
  libxml2 2.15.4-1.1  [High]  AVG-2898
  linux-cachyos-lts 6.18.55-1  [High]  AVG-2701
  systemd 262-1  [Medium]  AVG-2893
  coreutils 9.12-2.1  [Medium]  AVG-2885
  openjpeg2 2.5.4-1.1  [Medium]  AVG-2850
  openssl 3.6.5-1.1  [Medium]  AVG-2765
  libtiff 4.7.2-1.1  [Medium]  AVG-2721
  linux-cachyos-lts 6.18.55-1  [Medium]  AVG-2683
  perl 5.42.2-2.1  [Medium]  AVG-2630
  linux-cachyos 7.2.9-1  [Medium]  AVG-1879
  libheif 1.23.5-1.1  [Medium]  AVG-2520
  openvpn 2.7.7-1.1  [Medium]  AVG-2367
  linux-cachyos 7.2.9-1  [Medium]  AVG-2345
  perl 5.42.2-2.1  [Medium]  AVG-2264
  cpio 2.15-3.1  [Medium]  AVG-2262
  wget 1.25.0-6  [Medium]  AVG-1892
  giflib 6.1.3-2.1  [Medium]  AVG-1855
  xdg-utils 1.2.1-2  [Medium]  AVG-1420
  perl 5.42.2-2.1  [Low]  AVG-2890
  openssl 3.6.5-1.1  [Low]  AVG-2882
  lua51 5.1.5-13.1  [Low]  AVG-1302
  linux-cachyos 7.2.9-1  [Low]  AVG-1594
```

## How it works

1. Lists installed packages with `pacman -Q`.
2. Downloads advisory feed from the Arch Security Tracker.
3. Translates CachyOS kernel names to the Arch names the tracker uses.
4. Compares versions with pacman's own `vercmp` and reports affected packages, sorted by severity.

## How is this different from arch-audit?

[arch-audit](https://gitlab.archlinux.org/archlinux/arch-audit) is the established tool for this job on Arch. This project is aimed at CachyOS specifically, starting with the kernel mapping, and is also a learning project built in the open. If you run plain Arch, arch-audit is the more better choice.

## Limitations

- **Coverage is limited to packages in the Arch Security Tracker.** CachyOS-only packages and AUR packages aren't checked, so their absence from the report does *not* mean they are safe.
- **The kernel mapping is an assumption.** Each CachyOS variant is assumed to track the matching Arch kernel. Release-candidate kernels (`linux-cachyos-rc`) are not mapped.
- **Kernel versions are compared on the upstream version only**, because package release numbers aren't comparable across distros.
- **Old "no fix released" entries in the feed may produce false positives.**
- It doesn't check whether your *running* kernel matches the installed one.

## Roadmap

- [x] Read installed packages
- [x] Fetch advisory data from the Arch Security Tracker
- [x] Match installed versions against advisories
- [x] Sort results by severity
- [x] CachyOS kernel mapping
- [ ] Unit tests
- [ ] Coverage report (checked / CachyOS-only / AUR)
- [ ] "Reboot needed" check for kernel updates
- [ ] Scheduled weekly runs
- [ ] Alerts for critical advisories
- [ ] AUR coverage

## Contributing

Issues and pull requests welcome. Reports from other CachyOS setups are especially useful: different kernel variants, and the v3, v4, and znver4 repos.

## License

[MIT](LICENSE)
