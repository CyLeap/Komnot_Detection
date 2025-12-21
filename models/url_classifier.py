import pickle
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
import pandas as pd


class URLClassifier:
    def __init__(self):
        self.model = None
        self.is_trained = False

    def train(self, features, labels):
        """Train the ML model with features and labels."""
        X_train, X_test, y_train, y_test = train_test_split(
            features, labels, test_size=0.2, random_state=42)

        self.model = LogisticRegression()
        self.model.fit(X_train, y_train)
        self.is_trained = True

        # Evaluate
        y_pred = self.model.predict(X_test)
        accuracy = accuracy_score(y_test, y_pred)
        print(f"Model trained with accuracy: {accuracy:.2f}")

    def predict(self, features):
        """Predict if a URL is malicious (1) or safe (0)."""
        if not self.is_trained:
            raise ValueError("Model not trained yet.")
        return self.model.predict([features])[0]

    def save_model(self, filepath):
        """Save the trained model to a file."""
        if self.model:
            with open(filepath, 'wb') as f:
                pickle.dump(self.model, f)

    def load_model(self, filepath):
        """Load a trained model from a file."""
        with open(filepath, 'rb') as f:
            self.model = pickle.load(f)
        self.is_trained = True
