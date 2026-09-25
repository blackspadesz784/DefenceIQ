"""Unit and integration tests for ML Anomaly Detection Layer.

Tests feature extraction, baseline training, IsolationForest anomaly detection,
cold-start fallback, persistence, and RiskScoring/EventCorrelator integration.
"""

import os
import pytest

from sentinellayer.agent.ai_engine.ml_anomaly import (
    MLAnomalyDetector,
    generate_default_baseline_data,
    FEATURE_NAMES,
)
from sentinellayer.agent.ai_engine.risk_scoring import RiskScoringEngine
from sentinellayer.agent.ai_engine.event_correlator import EventCorrelator
from sentinellayer.agent.monitors.process_monitor import ProcessEvent


def test_feature_names_and_baseline_data():
    assert len(FEATURE_NAMES) == 6
    baseline = generate_default_baseline_data(n_samples=50)
    assert len(baseline) == 50
    for vec in baseline:
        assert len(vec) == 6
        assert all(isinstance(val, (int, float)) for val in vec)


def test_feature_extractor_values():
    detector = MLAnomalyDetector(auto_train=False)

    proc_data = {"cpu_percent": 12.5, "memory_rss_mb": 150.0, "child_count": 2}
    net_data = {"open_connections": 4}
    file_data = {"file_write_burst": 3, "entropy_delta": 1.2}

    vec = detector.extract_features(proc_data, net_data, file_data)
    assert vec == [12.5, 150.0, 4.0, 3.0, 1.2, 2.0]


def test_unfitted_model_graceful_fallback():
    # Model created without training
    detector = MLAnomalyDetector(auto_train=False)
    assert detector._is_fitted is False

    res = detector.predict_vector([50.0, 500.0, 10.0, 10.0, 2.0, 1.0])
    assert res["is_anomaly"] is False
    assert res["status"] == "UNFITTED"
    assert res["score"] == 0.0

    eval_res = detector.evaluate_telemetry({"cpu_percent": 99.0})
    assert eval_res is None


def test_baseline_training_and_normal_prediction():
    detector = MLAnomalyDetector(contamination=0.05, n_estimators=25, auto_train=True)
    assert detector._is_fitted is True

    # Typical normal background process (e.g. svchost or notepad)
    normal_vector = [1.2, 45.0, 0.0, 0.0, 0.0, 0.0]
    pred = detector.predict_vector(normal_vector)
    assert pred["is_anomaly"] is False
    assert pred["status"] == "EVALUATED"


def test_anomaly_detection_for_severe_outlier():
    detector = MLAnomalyDetector(contamination=0.05, n_estimators=25, auto_train=True)

    # Severe abnormal activity: 98% CPU, 2.5GB RAM, 75 sockets, 100 files modified, 7.9 entropy delta
    outlier_vector = [98.0, 2500.0, 75.0, 100.0, 7.9, 8.0]
    pred = detector.predict_vector(outlier_vector)
    assert pred["is_anomaly"] is True
    assert pred["confidence"] > 0.0

    # Evaluate telemetry helper
    eval_res = detector.evaluate_telemetry(
        proc_info={"name": "malware.exe", "pid": 4444, "cpu_percent": 98.0, "memory_rss_mb": 2500.0, "child_count": 8},
        net_info={"open_connections": 75},
        file_info={"file_write_burst": 100, "entropy_delta": 7.9},
    )
    assert eval_res is not None
    assert eval_res["signal"] == "ml_anomaly_detected"
    assert eval_res["confidence"] > 0.0


def test_model_save_and_load(tmp_path):
    model_file = str(tmp_path / "test_iso_forest.pkl")

    # Train and save
    detector = MLAnomalyDetector(n_estimators=30, auto_train=True)
    assert detector.save_model(model_file) is True
    assert os.path.isfile(model_file)

    # Load in new detector instance
    detector2 = MLAnomalyDetector(model_path=model_file, auto_train=False)
    assert detector2._is_fitted is True
    status = detector2.get_status()
    assert status["fitted"] is True


def test_risk_scoring_engine_ml_anomaly_signal():
    engine = RiskScoringEngine()

    # Verify signal definition and weight
    assert "ml_anomaly_detected" in engine.SIGNAL_DEFINITIONS
    weight = engine.get_signal_weight("ml_anomaly_detected")
    assert weight == 15

    # Compute score with ml_anomaly_detected
    signals = ["ml_anomaly_detected"]
    res = engine.calculate_score(signals)
    assert res.score == 15
    assert res.band == "GREEN"  # 0-24 is GREEN
    assert any(s.name == "ml_anomaly_detected" for s in res.contributing_signals)

    # Combine with suspicious script shell (+20) -> 35 (YELLOW)
    signals.append("spawned_script_shell")
    res2 = engine.calculate_score(signals)
    assert res2.score == 35
    assert res2.band == "YELLOW"


def test_event_correlator_ml_integration():
    detector = MLAnomalyDetector(contamination=0.05, n_estimators=25, auto_train=True)
    correlator = EventCorrelator(ml_anomaly_detector=detector)

    # Trigger process event with extreme outlier telemetry
    ev = ProcessEvent(
        pid=9999,
        ppid=1000,
        name="crypto_miner.exe",
        exe=r"C:\Windows\Temp\crypto_miner.exe",
        cmdline=["crypto_miner.exe", "-t", "16"],
        username="SYSTEM",
        cpu_percent=99.0,
        memory_mb=1800.0,
        signals=["resource_spike_cpu"],
    )

    incident = correlator.process_event(ev)
    assert incident is not None
    # Verify ml_anomaly_detected was automatically attached by correlator
    assert "ml_anomaly_detected" in incident.signals
    assert "resource_spike_cpu" in incident.signals
    # Score should combine resource_spike_cpu (+5) + ml_anomaly_detected (+15) = 20 (GREEN)
    assert incident.score_result.score == 20

    # Adding a script shell (+20) elevates it to 40 (YELLOW)
    ev2 = ProcessEvent(
        pid=9999,
        ppid=1000,
        name="crypto_miner.exe",
        signals=["spawned_script_shell"],
    )
    incident2 = correlator.process_event(ev2)
    assert incident2.score_result.score == 40
    assert incident2.score_result.band == "YELLOW"
