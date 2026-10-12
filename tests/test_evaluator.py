import pandas as pd
import pytest

from evaluator.evaluator import Evaluator


def test_jensen_shannon_distance_is_zero_for_identical_distributions():
    ev = Evaluator("icmp")
    series = pd.Series([1, 2, 3, 4, 5] * 20)

    dist = ev._jensen_shannon_distance(series, series)
    assert dist == pytest.approx(0.0, abs=1e-6)


def test_jensen_shannon_distance_is_positive_for_different_distributions():
    ev = Evaluator("icmp")
    real = pd.Series([1] * 100)
    sim = pd.Series([100] * 100)

    dist = ev._jensen_shannon_distance(real, sim)
    assert dist > 0


def test_jensen_shannon_distance_handles_empty_series():
    ev = Evaluator("icmp")
    empty = pd.Series([], dtype=float)
    other = pd.Series([1, 2, 3])

    import math
    assert math.isnan(ev._jensen_shannon_distance(empty, other))


def test_feature_summary_line_reports_deltas_from_real_mean():
    ev = Evaluator("icmp")
    real_df = pd.DataFrame({"packet_count": [10, 10, 10]})
    old_df = pd.DataFrame({"packet_count": [8, 8, 8]})
    new_df = pd.DataFrame({"packet_count": [10, 10, 10]})

    line = ev._feature_summary_line("packet_count", real_df, old_df, new_df)

    assert "delta_old=-2.0000" in line
    assert "delta_new=0.0000" in line


def _write_csv(path, values):
    pd.DataFrame({
        "packet_count": values,
        "flow_duration": [v * 0.1 for v in values],
        "total_bytes": [v * 100 for v in values],
        "avg_packet_size": [v * 10 for v in values],
        "iat_mean": [v * 0.01 for v in values],
    }).to_csv(path, index=False)


def test_flow_evaluation_two_way_writes_report_and_pngs(isolated_cwd):
    real_csv = isolated_cwd / "real.csv"
    old_csv = isolated_cwd / "old.csv"
    new_csv = isolated_cwd / "new.csv"

    _write_csv(real_csv, list(range(2, 20)))
    _write_csv(old_csv, list(range(2, 20)))
    _write_csv(new_csv, list(range(2, 20)))

    ev = Evaluator("icmp")
    report_path = ev.flow_evaluation_two_way(str(real_csv), str(old_csv), str(new_csv))

    assert (isolated_cwd / report_path).exists() or __import__("os").path.exists(report_path)
    content = open(report_path).read()
    assert "packet_count" in content
    assert "KS real-old" in content


def test_flow_evaluation_three_way_writes_report(isolated_cwd):
    real_csv = isolated_cwd / "real.csv"
    old_csv = isolated_cwd / "old.csv"
    new_csv = isolated_cwd / "new.csv"

    _write_csv(real_csv, list(range(2, 20)))
    _write_csv(old_csv, list(range(2, 20)))
    _write_csv(new_csv, list(range(2, 20)))

    ev = Evaluator("icmp")
    report_path = ev.flow_evaluation_three_way(str(real_csv), str(old_csv), str(new_csv))

    content = open(report_path).read()
    assert "Three-way evaluation" in content
