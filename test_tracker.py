from tracker import (
    clean,
    classify_package,
    coverage_buckets,
    format_match,
    index_tracker_by_name,
    is_affected,
    looks_stale,
    to_tracker_name,
    upstream_version,
)


def group(status, fixed):
    """Build a minimal advisory group for testing."""
    return {"status": status, "fixed": fixed}


# --- upstream_version -------------------------------------------------


def test_upstream_version_strips_arch_tag_and_pkgrel():
    assert upstream_version("6.17.2.arch1-1") == "6.17.2"


def test_upstream_version_strips_hardened_tag():
    assert upstream_version("5.17.9.hardened1-1") == "5.17.9"


def test_upstream_version_handles_plain_cachyos_version():
    assert upstream_version("6.17.1-2") == "6.17.1"


# --- name mapping -----------------------------------------------------


def test_cachyos_kernels_map_to_arch_names():
    assert to_tracker_name("linux-cachyos") == "linux"
    assert to_tracker_name("linux-cachyos-lts") == "linux-lts"


def test_ordinary_packages_keep_their_name():
    assert to_tracker_name("openssl") == "openssl"


def test_index_groups_kernels_under_the_tracker_name():
    installed = {
        "linux-cachyos": "6.17.1-2",
        "linux-cachyos-bore": "6.17.1-1",
        "openssl": "3.3.1-1",
    }
    index = index_tracker_by_name(installed)
    assert index["linux"] == [
        ("linux-cachyos", "6.17.1-2"),
        ("linux-cachyos-bore", "6.17.1-1"),
    ]
    assert index["openssl"] == [("openssl", "3.3.1-1")]


# --- is_affected ------------------------------------------------------


def test_fixed_but_not_yet_updated_is_flagged():
    assert is_affected("1.4.2-2", group("Fixed", "1.4.3-1")) is True


def test_fixed_and_already_updated_is_clean():
    assert is_affected("1.4.3-1", group("Fixed", "1.4.3-1")) is False


def test_not_affected_is_never_flagged():
    assert is_affected("1.0-1", group("Not affected", "2.0-1")) is False


def test_vulnerable_with_no_fix_is_flagged():
    assert is_affected("1.0-1", group("Vulnerable", None)) is True


def test_unknown_with_no_fix_is_not_flagged():
    assert is_affected("1.0-1", group("Unknown", None)) is False


def test_cachyos_rebuild_of_arch_package_is_covered():
    repos = {"bash": {"cachyos-znver4", "core"}}
    assert classify_package("bash", repos) == "covered"


def test_znver4_repo_names_count_as_cachyos():
    repos = {"cachyos-settings": {"cachyos-znver4"}}
    assert classify_package("cachyos-settings", repos) == "cachyos_only"


def test_numeric_versions_compare_as_numbers_not_text():
    # As plain text "3.9" sorts after "3.10"; as versions it is older.
    assert is_affected("3.9-1", group("Fixed", "3.10-1")) is True


def test_epoch_beats_version_number():
    assert is_affected("1:1.0-1", group("Fixed", "2.0-1")) is False


def test_cachyos_rebuild_pkgrel_is_clean():
    assert is_affected("1.4.3-1.1", group("Fixed", "1.4.3-1")) is False


def test_cachyos_kernel_older_than_fix_is_flagged():
    fixed = group("Fixed", "6.17.2.arch1-1")
    assert is_affected("6.17.1-2", fixed, kernel=True) is True


def test_cachyos_kernel_at_fix_version_is_clean():
    fixed = group("Fixed", "6.17.2.arch1-1")
    assert is_affected("6.17.2-1", fixed, kernel=True) is False


def test_cachyos_kernel_newer_than_fix_is_clean():
    fixed = group("Fixed", "6.17.2.arch1-1")
    assert is_affected("6.18.0-1", fixed, kernel=True) is False


def match(**overrides):
    """Build a match dict with sensible defaults, overriding what a test cares about."""
    base = {
        "package": "pam",
        "installed": "1.7.3-1.1",
        "fixed": None,
        "severity": "High",
        "group": "AVG-2901",
        "stale": False,
        "affected": None,
    }
    return {**base, **overrides}


def test_format_match_with_no_fix_and_not_stale():
    assert format_match(match()) == "  pam 1.7.3-1.1  [High]  AVG-2901"


def test_format_match_shows_the_upgrade_when_a_fix_exists():
    line = format_match(match(installed="1.0-1", fixed="2.0-1"))
    assert line == "  pam 1.0-1 -> 2.0-1  [High]  AVG-2901"


def test_format_match_notes_what_the_tracker_last_recorded_for_stale_entries():
    line = format_match(match(stale=True, affected="5.15.8.arch1-1"))
    assert "(tracker last recorded: 5.15.8.arch1-1)" in line
    assert line.endswith("https://security.archlinux.org/AVG-2901")


def test_old_affected_version_marks_entry_stale():
    group = {"status": "Vulnerable", "fixed": None, "affected": "5.15.8.arch1-1"}
    assert looks_stale("7.2.9-1", group) is True


def test_cachyos_rebuild_of_affected_version_is_not_stale():
    # pkgrel 1.1 is newer than 1, but the upstream version is the same
    group = {"status": "Vulnerable", "fixed": None, "affected": "1.7.3-1"}
    assert looks_stale("1.7.3-1.1", group) is False


def test_groups_with_a_fix_are_never_stale():
    group = {"status": "Fixed", "fixed": "2.0-1", "affected": "1.0-1"}
    assert looks_stale("1.0-1", group) is False
    
    
def test_package_only_in_cachyos_repo_is_not_covered():
    repos = {"cachyos-settings": {"cachyos"}}
    assert classify_package("cachyos-settings", repos) == "cachyos_only"


def test_package_in_no_sync_repo_is_foreign():
    assert classify_package("some-aur-tool", {}) == "foreign"


def test_cachyos_kernel_is_mapped_even_though_only_cachyos_offers_it():
    repos = {"linux-cachyos": {"cachyos"}}
    assert classify_package("linux-cachyos", repos) == "mapped"


def test_coverage_buckets_sort_every_package_exactly_once():
    installed = {"openssl": "1-1", "mystery": "2-1"}
    repos = {"openssl": {"core"}}
    buckets = coverage_buckets(installed, repos)
    assert buckets["covered"] == ["openssl"]
    assert buckets["foreign"] == ["mystery"]
    group = {"status": "Vulnerable", "fixed": None, "affected": None}
    assert looks_stale("1.0-1", group) is False


def test_clean_removes_control_characters():
    assert clean("1.0\x08-1") == "1.0-1"


def test_clean_defangs_ansi_escape_sequences():
    assert "\x1b" not in clean("\x1b[2Jhello")


def test_format_match_strips_control_characters_from_feed_data():
    line = format_match(match(group="AVG-1\x1b[2J"))
    assert "\x1b" not in line

def test_arch_repo_package_is_covered():
    repos = {"openssl": {"cachyos-v3", "core"}}
    assert classify_package("openssl", repos) == "covered"


def test_package_only_in_cachyos_repo_is_not_covered():
    repos = {"cachyos-settings": {"cachyos"}}
    assert classify_package("cachyos-settings", repos) == "cachyos_only"


def test_package_in_no_sync_repo_is_foreign():
    assert classify_package("some-aur-tool", {}) == "foreign"


def test_cachyos_kernel_is_mapped_even_though_only_cachyos_offers_it():
    repos = {"linux-cachyos": {"cachyos"}}
    assert classify_package("linux-cachyos", repos) == "mapped"


def test_coverage_buckets_sort_every_package_exactly_once():
    installed = {"openssl": "1-1", "mystery": "2-1"}
    repos = {"openssl": {"core"}}
    buckets = coverage_buckets(installed, repos)
    assert buckets["covered"] == ["openssl"]
    assert buckets["foreign"] == ["mystery"]