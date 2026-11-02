"""Scope matching: wildcards, CIDRs, and out_of_scope always winning."""
import pytest

from redpent_tools.scope import ScopeError


def test_exact_domain_in_scope(ctx):
    d = ctx.guard.decide("example.com")
    assert d.in_scope


def test_wildcard_subdomain_in_scope(ctx):
    assert ctx.guard.decide("api.example.com").in_scope
    assert ctx.guard.decide("deep.nested.example.com").in_scope


def test_unrelated_domain_out_of_scope(ctx):
    assert not ctx.guard.decide("evil.com").in_scope


def test_out_of_scope_wins_over_wildcard(ctx):
    # admin.example.com matches *.example.com but is explicitly out of scope.
    d = ctx.guard.decide("admin.example.com")
    assert not d.in_scope
    assert "out_of_scope" in d.reason


def test_cidr_ip_in_scope(ctx):
    assert ctx.guard.decide("203.0.113.5").in_scope


def test_cidr_ip_out_of_scope_wins(ctx):
    assert not ctx.guard.decide("203.0.113.10").in_scope


def test_ip_outside_all_cidrs(ctx):
    assert not ctx.guard.decide("198.51.100.1").in_scope


def test_cidr_block_within_scope(ctx):
    # .16/28 is inside 203.0.113.0/24 and does NOT contain the OOS .10
    assert ctx.guard.decide("203.0.113.16/28").in_scope



def test_cidr_block_overlapping_oos_rejected(ctx):
    # 203.0.113.8/29 contains the OOS 203.0.113.10/32
    assert not ctx.guard.decide("203.0.113.8/29").in_scope


def test_assert_in_scope_raises(ctx):
    with pytest.raises(ScopeError):
        ctx.guard.assert_in_scope("evil.com")


def test_url_host_stripping(ctx):
    assert ctx.guard.decide("https://api.example.com/path?x=1").in_scope
