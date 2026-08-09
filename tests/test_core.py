"""Tests for the pure core helpers shared by the single-file app."""
import importlib.util
import pathlib

import pytest


@pytest.fixture(scope="module")
def module():
    root = pathlib.Path(__file__).resolve().parent.parent
    spec = importlib.util.spec_from_file_location(
        "core_en", str(root / "magnet_share.en.py")
    )
    mod = importlib.util.module_from_spec(spec)
    # Do NOT run initialize_database on import for pure-function tests:
    # exec_module runs the module top-level. Provide a throwaway path first.
    spec.loader.exec_module(mod)
    return mod


def test_infohash_hex_lowercase(module):
    assert (
        module.extract_infohash(
            "magnet:?xt=urn:btih:0123456789abcdef0123456789abcdef01234567"
        )
        == "0123456789abcdef0123456789abcdef01234567"
    )


def test_infohash_hex_uppercase_normalized_to_lower(module):
    assert (
        module.extract_infohash(
            "magnet:?xt=urn:btih:ABCDEF0123456789ABCDEF0123456789ABCDEF01"
        )
        == "abcdef0123456789abcdef0123456789abcdef01"
    )


def test_infohash_base32_kept_upper(module):
    # 40 hex chars = 32 base32 chars; known btih. Use a synthetic 32-char B32.
    b32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"  # 32 chars
    assert module.extract_infohash(f"magnet:?xt=urn:btih:{b32}") == b32


def test_infohash_rejects_non_magnet(module):
    with pytest.raises(ValueError):
        module.extract_infohash("http://example.com/file.torrent")


def test_infohash_rejects_missing_xt(module):
    with pytest.raises(ValueError):
        module.extract_infohash("magnet:?dn=name")


def test_infohash_rejects_bad_length(module):
    with pytest.raises(ValueError):
        module.extract_infohash("magnet:?xt=urn:btih:abc123")


def test_lcs_full_subsequence_scores_one(module):
    assert module.longest_common_subsequence_score("ubuntu", "Ubuntu ISO 2024") == 1.0


def test_lcs_partial(module):
    # "uxnt": u and n and t present in order, x is missing, so partial.
    score = module.longest_common_subsequence_score("uxnt", "ubuntu")
    assert 0.0 < score < 1.0


def test_lcs_no_match_zero(module):
    assert module.longest_common_subsequence_score("zzzz", "abcde") == 0.0


def test_lcs_empty_zero(module):
    assert module.longest_common_subsequence_score("", "abc") == 0.0
    assert module.longest_common_subsequence_score("abc", "") == 0.0
