"""Tests for the frozen relaxed replay evaluator."""

from replay_relaxed import micro_aggregate, score_replay


A, B, C = "A", "B", "C"


def test_replay_scores_prediction_only_after_it_is_built():
    report = score_replay(
        strict_groups=[[A, B]], rescue_groups=[[A, B]],
        strict_relaxed_groups=[[A, B], [A, B, C]],
        rescue_relaxed_groups=[[A, B], [A, B, C]],
        ground_truth={"symbols": {}, "origins": [{"origin": "O", "members": [A, B, C]}]},
        universe={A, B, C}, neutral={},
    )
    assert report["strict"]["true_positive"] == 1
    assert report["strict_relaxed"]["true_positive"] == 3


def test_micro_aggregate_sums_pair_counts_before_rounding():
    one = score_replay(
        strict_groups=[[A, B]], rescue_groups=[[A, B]],
        strict_relaxed_groups=[[A, B]], rescue_relaxed_groups=[[A, B]],
        ground_truth={"symbols": {}, "origins": [{"origin": "O", "members": [A, B]}]},
        universe={A, B}, neutral={}, v0_groups=[],
    )
    two = score_replay(
        strict_groups=[], rescue_groups=[],
        strict_relaxed_groups=[], rescue_relaxed_groups=[],
        ground_truth={"symbols": {}, "origins": [{"origin": "O", "members": [A, B]}]},
        universe={A, B}, neutral={}, v0_groups=[],
    )
    micro = micro_aggregate([one, two])
    assert micro["strict"]["true_positive"] == 1
    assert micro["strict"]["false_negative"] == 1


if __name__ == "__main__":
    test_replay_scores_prediction_only_after_it_is_built()
    test_micro_aggregate_sums_pair_counts_before_rounding()
    print("test_replay_relaxed: PASS")
