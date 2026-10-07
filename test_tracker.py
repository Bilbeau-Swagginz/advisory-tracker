from tracker import (
    index_tracker_by_name,
    is_affected,
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
