from ctoai_lint import cli
import json, subprocess, sys, os

def test_scan_demo():
    # audyt katalogu tests/ (zawiera sample_cpp.cpp ze strcpy/sprintf)
    res = cli.audit("tests")
    assert res["files"] >= 1, res
    assert res["high"] >= 1, res  # strcpy/sprintf to high
    assert 0 <= res["health"] <= 100
    print("TEST audit:", json.dumps(res, ensure_ascii=False))

def test_cli_runs():
    r = cli.main(["tests", "--json"])
    assert r == 0

if __name__ == "__main__":
    test_scan_demo()
    test_cli_runs()
    print("ALL TESTS PASSED")
