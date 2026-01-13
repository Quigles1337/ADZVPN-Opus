"""
Anomaly Detector

Detects anomalous traffic patterns using Isolation Forest.

Isolation Forest is an unsupervised learning algorithm that
isolates anomalies by randomly selecting features and split values.
Anomalies are easier to isolate, requiring fewer splits.

Created by: ADZ (Alexander David Zalewski) & Claude Opus 4.5
"""

import sys
from pathlib import Path
from typing import List, Optional, Tuple
import numpy as np
from dataclasses import dataclass

# Add parent for silver constants
sys.path.insert(0, str(Path(__file__).parent.parent))
from silver_constants import DELTA_S, TAU

from .models import (
    TrafficFeatures,
    ThreatLevel,
    ThreatCategory,
    ThreatAlert,
)

# Try to import sklearn, fall back to simple implementation
try:
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False


@dataclass
class AnomalyResult:
    """Result of anomaly detection."""
    is_anomaly: bool
    anomaly_score: float  # -1 to 1, where < 0 is anomaly
    normalized_score: float  # 0 to 1, where higher = more anomalous
    feature_contributions: dict  # Which features contributed most


class AnomalyDetector:
    """
    Anomaly detector using Isolation Forest.

    Detects unusual patterns that don't fit established baselines.
    """

    def __init__(
        self,
        contamination: float = 0.1,
        n_estimators: int = 100,
        threshold: float = 0.5,
    ):
        """
        Initialize the anomaly detector.

        Args:
            contamination: Expected proportion of anomalies (0-0.5)
            n_estimators: Number of trees in the forest
            threshold: Score threshold for anomaly (0-1)
        """
        self.contamination = contamination
        self.n_estimators = n_estimators
        self.threshold = threshold

        # Model state
        self._model: Optional[IsolationForest] = None
        self._scaler: Optional[StandardScaler] = None
        self._is_fitted = False
        self._training_data: List[List[float]] = []
        self._min_training_samples = 50

    def _init_model(self) -> None:
        """Initialize the Isolation Forest model."""
        if SKLEARN_AVAILABLE:
            self._model = IsolationForest(
                contamination=self.contamination,
                n_estimators=self.n_estimators,
                random_state=42,
                n_jobs=-1,
            )
            self._scaler = StandardScaler()
        else:
            self._model = None
            self._scaler = None

    def train(self, samples: List[TrafficFeatures]) -> bool:
        """
        Train the model on normal traffic samples.

        Args:
            samples: List of normal traffic samples

        Returns:
            True if training succeeded
        """
        if not SKLEARN_AVAILABLE:
            return False

        if len(samples) < self._min_training_samples:
            return False

        # Convert to feature vectors
        X = np.array([s.to_feature_vector() for s in samples])

        # Initialize and fit scaler
        self._init_model()
        X_scaled = self._scaler.fit_transform(X)

        # Fit isolation forest
        self._model.fit(X_scaled)
        self._is_fitted = True

        return True

    def add_training_sample(self, sample: TrafficFeatures) -> None:
        """Add a sample to training data (for incremental learning)."""
        self._training_data.append(sample.to_feature_vector())

        # Auto-train when we have enough samples
        if len(self._training_data) >= self._min_training_samples and not self._is_fitted:
            self._auto_train()

    def _auto_train(self) -> None:
        """Automatically train on accumulated data."""
        if not SKLEARN_AVAILABLE or len(self._training_data) < self._min_training_samples:
            return

        X = np.array(self._training_data)
        self._init_model()
        X_scaled = self._scaler.fit_transform(X)
        self._model.fit(X_scaled)
        self._is_fitted = True

    def detect(self, features: TrafficFeatures) -> AnomalyResult:
        """
        Detect if traffic features are anomalous.

        Args:
            features: Traffic features to analyze

        Returns:
            AnomalyResult with detection details
        """
        # If model not fitted, use heuristic detection
        if not self._is_fitted or not SKLEARN_AVAILABLE:
            return self._heuristic_detect(features)

        # Convert to feature vector
        X = np.array([features.to_feature_vector()])
        X_scaled = self._scaler.transform(X)

        # Get anomaly score (-1 for anomaly, 1 for normal)
        raw_score = self._model.decision_function(X_scaled)[0]
        prediction = self._model.predict(X_scaled)[0]

        # Normalize score to 0-1 (higher = more anomalous)
        # Raw score is typically in range [-0.5, 0.5]
        normalized_score = max(0, min(1, 0.5 - raw_score))

        # Calculate feature contributions (approximate)
        contributions = self._calculate_contributions(features, X_scaled[0])

        return AnomalyResult(
            is_anomaly=prediction == -1 or normalized_score > self.threshold,
            anomaly_score=raw_score,
            normalized_score=normalized_score,
            feature_contributions=contributions,
        )

    def _heuristic_detect(self, features: TrafficFeatures) -> AnomalyResult:
        """
        Fallback heuristic detection when model isn't trained.

        Uses silver-ratio scaled thresholds.
        """
        score = 0.0
        contributions = {}

        # Check for extreme values
        feature_names = TrafficFeatures.feature_names()
        feature_values = features.to_feature_vector()

        # Bytes sent (threshold: 100MB)
        if features.bytes_sent > 100_000_000:
            contrib = min((features.bytes_sent / 100_000_000 - 1) / DELTA_S, 0.3)
            score += contrib
            contributions["bytes_sent"] = contrib

        # Bytes ratio (threshold: 10x)
        if features.bytes_ratio > 10:
            contrib = min((features.bytes_ratio - 10) / 20, 0.3)
            score += contrib
            contributions["bytes_ratio"] = contrib

        # Unique destinations (threshold: 100)
        if features.unique_destinations > 100:
            contrib = min((features.unique_destinations - 100) / 200, 0.2)
            score += contrib
            contributions["unique_destinations"] = contrib

        # Failed connections (threshold: 50%)
        if features.connection_count > 0:
            failure_rate = features.failed_connections / features.connection_count
            if failure_rate > 0.5:
                contrib = min(failure_rate - 0.5, 0.2)
                score += contrib
                contributions["failed_connections"] = contrib

        # Very low packet interval variance (beaconing)
        if features.packet_interval_variance < 0.1 and features.packets_sent > 10:
            contrib = 0.3
            score += contrib
            contributions["packet_interval_variance"] = contrib

        # Normalize
        normalized_score = min(score, 1.0)

        return AnomalyResult(
            is_anomaly=normalized_score > self.threshold,
            anomaly_score=0.5 - normalized_score,  # Match sklearn convention
            normalized_score=normalized_score,
            feature_contributions=contributions,
        )

    def _calculate_contributions(
        self,
        features: TrafficFeatures,
        scaled_features: np.ndarray,
    ) -> dict:
        """
        Estimate which features contributed to anomaly score.

        This is an approximation based on how far each feature
        is from the mean (in standard deviations).
        """
        contributions = {}
        feature_names = TrafficFeatures.feature_names()

        # Features further from 0 (in scaled space) contribute more
        for i, (name, value) in enumerate(zip(feature_names, scaled_features)):
            # Absolute deviation from mean (0 in scaled space)
            deviation = abs(value)
            if deviation > 2.0:  # More than 2 std devs
                contributions[name] = min(deviation / 4.0, 1.0)

        return contributions

    def create_alert(
        self,
        features: TrafficFeatures,
        result: AnomalyResult,
    ) -> Optional[ThreatAlert]:
        """
        Create a threat alert from anomaly detection result.

        Returns None if not anomalous enough.
        """
        if not result.is_anomaly:
            return None

        # Determine threat level from score
        threat_level = ThreatLevel.from_score(result.normalized_score)

        # Build indicators from contributions
        indicators = []
        for feature, contrib in sorted(
            result.feature_contributions.items(),
            key=lambda x: x[1],
            reverse=True,
        )[:5]:
            indicators.append(f"{feature}: contribution {contrib:.2f}")

        return ThreatAlert(
            threat_level=threat_level,
            threat_category=ThreatCategory.SUSPICIOUS,
            confidence=min(0.4 + result.normalized_score * 0.5, 0.9),
            source="anomaly_detector",
            session_id=features.session_id,
            client_id=features.client_id,
            description="Anomalous traffic pattern detected by AI model",
            indicators=indicators,
            recommendations=[
                "Review traffic patterns manually",
                "Check for compromised client",
                "Monitor for continued anomalies",
            ],
            raw_features={
                "anomaly_score": result.anomaly_score,
                "normalized_score": result.normalized_score,
            },
        )

    def analyze(self, features: TrafficFeatures) -> Optional[ThreatAlert]:
        """
        Analyze traffic and return alert if anomalous.

        Convenience method combining detect() and create_alert().
        """
        result = self.detect(features)
        return self.create_alert(features, result)

    @property
    def is_trained(self) -> bool:
        """Check if the model is trained."""
        return self._is_fitted


class SimpleIsolationForest:
    """
    Simple Isolation Forest implementation for when sklearn is unavailable.

    This is a basic implementation for educational purposes.
    """

    def __init__(self, n_trees: int = 100, sample_size: int = 256):
        self.n_trees = n_trees
        self.sample_size = sample_size
        self.trees: List[dict] = []

    def fit(self, X: np.ndarray) -> None:
        """Fit the isolation forest."""
        n_samples, n_features = X.shape

        for _ in range(self.n_trees):
            # Sample subset
            if n_samples > self.sample_size:
                indices = np.random.choice(n_samples, self.sample_size, replace=False)
                X_sample = X[indices]
            else:
                X_sample = X

            # Build tree
            tree = self._build_tree(X_sample, 0, int(np.ceil(np.log2(self.sample_size))))
            self.trees.append(tree)

    def _build_tree(self, X: np.ndarray, depth: int, max_depth: int) -> dict:
        """Recursively build an isolation tree."""
        n_samples, n_features = X.shape

        # Termination conditions
        if depth >= max_depth or n_samples <= 1:
            return {"type": "leaf", "size": n_samples}

        # Randomly select feature and split value
        feature_idx = np.random.randint(n_features)
        feature_values = X[:, feature_idx]
        min_val, max_val = feature_values.min(), feature_values.max()

        if min_val == max_val:
            return {"type": "leaf", "size": n_samples}

        split_value = np.random.uniform(min_val, max_val)

        # Split data
        left_mask = feature_values < split_value
        right_mask = ~left_mask

        return {
            "type": "node",
            "feature": feature_idx,
            "split": split_value,
            "left": self._build_tree(X[left_mask], depth + 1, max_depth),
            "right": self._build_tree(X[right_mask], depth + 1, max_depth),
        }

    def predict(self, X: np.ndarray) -> np.ndarray:
        """Predict anomaly labels (-1 for anomaly, 1 for normal)."""
        scores = self.decision_function(X)
        return np.where(scores < 0, -1, 1)

    def decision_function(self, X: np.ndarray) -> np.ndarray:
        """Calculate anomaly scores."""
        n_samples = X.shape[0]
        scores = np.zeros(n_samples)

        for i in range(n_samples):
            path_lengths = [self._path_length(X[i], tree, 0) for tree in self.trees]
            avg_path_length = np.mean(path_lengths)

            # Normalize by expected path length
            c_n = 2 * (np.log(self.sample_size - 1) + 0.5772156649) - 2 * (self.sample_size - 1) / self.sample_size
            scores[i] = 0.5 - 2 ** (-avg_path_length / c_n)

        return scores

    def _path_length(self, x: np.ndarray, tree: dict, depth: int) -> float:
        """Calculate path length for a sample in a tree."""
        if tree["type"] == "leaf":
            # Add expected path length in subtree
            size = tree["size"]
            if size <= 1:
                return depth
            c_n = 2 * (np.log(size - 1) + 0.5772156649) - 2 * (size - 1) / size
            return depth + c_n

        if x[tree["feature"]] < tree["split"]:
            return self._path_length(x, tree["left"], depth + 1)
        else:
            return self._path_length(x, tree["right"], depth + 1)
