"""What the words on the What we run list match."""
import helpers
import inventory as INV


def matches(terms, item):
    return bool(INV.Matcher([{"name": "x", "terms": terms}]).match(INV.product_text(item)))


NOTICE = {"source": "ubuntu", "title": "OpenSSL vulnerabilities", "tags": [], "extra": {"packages": ["openssl", "libssl3"]}}
KERNEL = {"source": "ubuntu", "title": "Linux kernel vulnerabilities", "tags": [], "extra": {"packages": ["linux-aws"]}}


def test_ubuntu_matches_every_ubuntu_notice():
    assert matches(["Ubuntu"], NOTICE) and matches(["Ubuntu"], KERNEL)


def test_ubuntu_notices_still_match_by_package_and_title():
    assert matches(["OpenSSL"], NOTICE) and matches(["libssl3"], NOTICE) and matches(["Linux"], KERNEL)
    assert not matches(["Linux"], NOTICE)


def test_ubuntu_doesnt_match_other_sources_just_for_being_on_ubuntu():
    assert not matches(["Ubuntu"], {"source": "kev", "title": "Apache HTTP Server", "tags": ["Apache"], "extra": {}})
    assert not matches(["Ubuntu"], {"source": "msrc", "title": "x", "tags": ["Windows Paint"], "extra": {}})


def test_whole_words_only():
    assert not matches(["SSL"], NOTICE) and not matches(["Open"], NOTICE)


def test_truenas_not_affected_doesnt_count():
    assert not matches(["TrueNAS"], {"source": "truenas", "title": "x", "tags": [], "extra": {"level": "none"}})
    assert matches(["TrueNAS"], {"source": "truenas", "title": "x", "tags": [], "extra": {"level": "medium"}})


helpers.run_tests(globals())
