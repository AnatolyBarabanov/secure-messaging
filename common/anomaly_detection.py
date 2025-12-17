# This file implements a simple AI-based anomaly detection system
# It uses an Isolation Forest model to detect abnormal messages

from typing import Tuple
import numpy as np
from sklearn.ensemble import IsolationForest


class AnomalyDetector:
    # AI anomaly detector based on message length (Unusually short or long messages may be flagged)

    def __init__(self):
        # Train the model on "normal" message lengths
        lengths = np.arange(10, 201).reshape(-1, 1)

        self.model = IsolationForest(
            contamination=0.10,
            random_state=42
        )
        self.model.fit(lengths)

    def score_message(self, message: str) -> Tuple[bool, float]:
        # Evaluates whether a message is anomalous.

        length = len(message)
        X = np.array([[length]])

        prediction = self.model.predict(X)[0]   # -1 = anomaly
        score = self.model.decision_function(X)[0]

        return prediction == -1, float(score)
