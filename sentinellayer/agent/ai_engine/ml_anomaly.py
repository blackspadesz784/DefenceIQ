"""Machine Learning Anomaly Detection Layer.

Provides lightweight, unsupervised baseline activity modeling using scikit-learn's
IsolationForest. Identifies statistical process, network, and file telemetry
outliers and contributes an auxiliary explainable signal ('ml_anomaly_detected')
to the deterministic RiskScoringEngine.
"""

import logging
import os
import pickle
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("defenceiq.ai_engine.ml_anomaly")

FEATURE_NAMES = [
    "cpu_percent",
    "memory_rss_mb",
    "open_connections",
    "file_write_burst",
    "entropy_delta",
    "child_process_count",
]


def generate_default_baseline_data(n_samples: int = 200) -> List[List[float]]:
    """Generates synthetic baseline clusters representing normal desktop process profiles.

    Covers:
      - Idle background services: CPU 0.0-2.0%, RAM 15-80MB, Sockets 0-1, File 0, Entropy 0.0, Children 0
      - Typical user applications (browsers, text editors): CPU 1.0-15.0%, RAM 80-450MB, Sockets 1-8, File 0-2, Entropy 0.0-1.5, Children 0-2
      - Compile / build tasks: CPU 20.0-60.0%, RAM 200-600MB, Sockets 0-2, File 2-8, Entropy 0.0-2.0, Children 1-4
    """
    import random
    random.seed(42)
    samples = []

    for _ in range(n_samples):
        r = random.random()
        if r < 0.60:
            # Idle/light background service
            cpu = random.uniform(0.0, 3.0)
            mem = random.uniform(10.0, 90.0)
            sock = random.choice([0, 0, 1])
            files = random.choice([0, 0, 0, 1])
            ent = random.uniform(0.0, 0.5)
            children = 0
        elif r < 0.90:
            # Normal interactive application
            cpu = random.uniform(1.0, 18.0)
            mem = random.uniform(80.0, 450.0)
            sock = random.randint(1, 8)
            files = random.randint(0, 3)
            ent = random.uniform(0.1, 1.8)
            children = random.choice([0, 1, 2])
        else:
            # Periodic busy productivity task
            cpu = random.uniform(15.0, 55.0)
            mem = random.uniform(200.0, 650.0)
            sock = random.randint(0, 4)
            files = random.randint(2, 6)
            ent = random.uniform(0.2, 2.2)
            children = random.randint(1, 3)

        samples.append([cpu, mem, sock, files, ent, children])

    return samples


class MLAnomalyDetector:
    """Unsupervised endpoint behavior anomaly detector using Isolation Forest."""

    DEFAULT_MODEL_FILE = os.path.join(
        os.path.dirname(__file__), "model", "isolation_forest.pkl"
    )

    def __init__(
        self,
        contamination: float = 0.05,
        n_estimators: int = 100,
        model_path: Optional[str] = None,
        auto_train: bool = True,
    ):
        self.contamination = contamination
        self.n_estimators = n_estimators
        self.model_path = model_path or self.DEFAULT_MODEL_FILE
        self._model = None
        self._is_fitted = False
        self._calibration_buffer: List[List[float]] = []
        self._buffer_capacity = 1000

        # Attempt to load saved model or train initial baseline
        loaded = self.load_model()
        if not loaded and auto_train:
            self.train_default_baseline()

    def train_default_baseline(self) -> bool:
        """Initializes model on pre-calibrated baseline distributions."""
        baseline = generate_default_baseline_data(n_samples=300)
        return self.train_baseline(baseline)

    def train_baseline(self, samples: List[List[float]]) -> bool:
        """Fits the IsolationForest on provided training samples."""
        if len(samples) < 10:
            logger.warning("Insufficient samples to train ML baseline (need >= 10)")
            return False

        try:
            from sklearn.ensemble import IsolationForest
            import numpy as np

            X = np.array(samples, dtype=float)
            clf = IsolationForest(
                n_estimators=self.n_estimators,
                contamination=self.contamination,
                random_state=42,
            )
            clf.fit(X)
            self._model = clf
            self._is_fitted = True
            logger.info(f"IsolationForest baseline fitted successfully on {len(samples)} samples.")
            return True
        except Exception as e:
            logger.error(f"Failed to fit IsolationForest baseline: {e}")
            self._is_fitted = False
            return False

    def extract_features(
        self,
        proc_info: Dict[str, Any],
        net_info: Optional[Dict[str, Any]] = None,
        file_info: Optional[Dict[str, Any]] = None,
    ) -> List[float]:
        """Converts heterogeneous monitor telemetry into normalized 6D feature vector."""
        cpu = float(proc_info.get("cpu_percent", 0.0) or 0.0)
        mem = float(proc_info.get("memory_rss_mb", 0.0) or 0.0)
        children = float(proc_info.get("child_count", 0) or 0.0)

        open_conns = 0.0
        if net_info:
            open_conns = float(net_info.get("open_connections", 0) or 0.0)

        file_burst = 0.0
        ent_delta = 0.0
        if file_info:
            file_burst = float(file_info.get("file_write_burst", 0) or 0.0)
            ent_delta = float(file_info.get("entropy_delta", 0.0) or 0.0)

        return [cpu, mem, open_conns, file_burst, ent_delta, children]

    def predict_vector(self, features: List[float]) -> Dict[str, Any]:
        """Evaluates a feature vector against the fitted isolation forest.

        Returns:
            dict containing:
              - is_anomaly (bool)
              - score (float): anomaly score (lower is more anomalous)
              - confidence (float): 0.0 to 1.0 confidence in anomaly
              - features (dict): named feature values
        """
        feature_dict = dict(zip(FEATURE_NAMES, features))

        if not self._is_fitted or self._model is None:
            return {
                "is_anomaly": False,
                "score": 0.0,
                "confidence": 0.0,
                "features": feature_dict,
                "status": "UNFITTED",
            }

        try:
            import numpy as np

            X = np.array([features], dtype=float)
            pred = self._model.predict(X)[0]  # -1 = anomaly, +1 = normal
            raw_score = float(self._model.score_samples(X)[0])  # typically -0.8 to -0.3

            is_anomaly = bool(pred == -1)

            # Map raw score to human-interpretable confidence (0.0 to 1.0)
            # score_samples < -0.65 indicates strong deviation
            confidence = max(0.0, min(1.0, (-raw_score - 0.45) * 3.0))

            return {
                "is_anomaly": is_anomaly,
                "score": round(raw_score, 4),
                "confidence": round(confidence, 3),
                "features": feature_dict,
                "status": "EVALUATED",
            }
        except Exception as e:
            logger.error(f"Error evaluating feature vector in ML detector: {e}")
            return {
                "is_anomaly": False,
                "score": 0.0,
                "confidence": 0.0,
                "features": feature_dict,
                "status": "ERROR",
            }

    def evaluate_telemetry(
        self,
        proc_info: Dict[str, Any],
        net_info: Optional[Dict[str, Any]] = None,
        file_info: Optional[Dict[str, Any]] = None,
    ) -> Optional[Dict[str, Any]]:
        """Evaluates process and environmental telemetry.

        Returns an anomaly payload if an outlier is identified, else None.
        """
        features = self.extract_features(proc_info, net_info, file_info)
        result = self.predict_vector(features)

        if result.get("is_anomaly"):
            logger.info(
                f"ML Anomaly detected for {proc_info.get('name', 'unknown')} (PID {proc_info.get('pid', 'N/A')}): "
                f"score={result['score']}, confidence={result['confidence']}"
            )
            return {
                "signal": "ml_anomaly_detected",
                "score": result["score"],
                "confidence": result["confidence"],
                "features": result["features"],
            }

        # Otherwise record normal observation into self-calibration buffer
        if len(self._calibration_buffer) < self._buffer_capacity:
            self._calibration_buffer.append(features)

        return None

    def save_model(self, path: Optional[str] = None) -> bool:
        """Persists trained model state to disk."""
        target = path or self.model_path
        if not self._is_fitted or self._model is None:
            return False

        try:
            os.makedirs(os.path.dirname(os.path.abspath(target)), exist_ok=True)
            with open(target, "wb") as f:
                pickle.dump(self._model, f)
            logger.info(f"Saved ML anomaly model to {target}")
            return True
        except Exception as e:
            logger.error(f"Failed to save ML anomaly model: {e}")
            return False

    def load_model(self, path: Optional[str] = None) -> bool:
        """Loads serialized model state from disk if present."""
        target = path or self.model_path
        if not os.path.isfile(target):
            return False

        try:
            with open(target, "rb") as f:
                self._model = pickle.load(f)
            self._is_fitted = True
            logger.info(f"Loaded ML anomaly model from {target}")
            return True
        except Exception as e:
            logger.warning(f"Could not load ML model from {target}: {e}")
            self._is_fitted = False
            return False

    def get_status(self) -> Dict[str, Any]:
        """Returns diagnostic status of the ML Anomaly Detection engine."""
        return {
            "fitted": self._is_fitted,
            "n_estimators": self.n_estimators,
            "contamination": self.contamination,
            "calibration_samples_collected": len(self._calibration_buffer),
            "model_path": self.model_path,
        }
