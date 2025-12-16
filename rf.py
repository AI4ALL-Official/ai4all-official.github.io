"""
baseline_rf_model.py
Baseline RandomForest model (no SMOTE) for credit default prediction.
"""

import os
import joblib
import pandas as pd

from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    roc_auc_score,
    confusion_matrix,
)

FILENAME = "Credit Card Defaulter Prediction.csv"
TARGET_COL = "default "  # note the space


def load_and_prepare_data(test_size=0.2, random_state=42):
    """Load CSV, clean, encode, and split into train/test."""
    if not os.path.exists(FILENAME):
        raise FileNotFoundError(
            f"File '{FILENAME}' not found. Put it in this folder or update FILENAME."
        )

    df = pd.read_csv(FILENAME)

    # Drop ID so that the model does not memorize IDs
    if "ID" in df.columns:
        df = df.drop(["ID"], axis=1)

    # Map target: Y->1, N->0
    if TARGET_COL not in df.columns:
        raise KeyError(f"Target column '{TARGET_COL}' not found in data.")

    df[TARGET_COL] = df[TARGET_COL].map({"N": 0, "Y": 1})

    # Split X / y
    X = df.drop(TARGET_COL, axis=1)
    y = df[TARGET_COL]

    # Ensure all X variables are numeric (get_dummies)
    X = pd.get_dummies(X, drop_first=True)

    # Train/test split (stratified on y)
    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=test_size,
        random_state=random_state,
        stratify=y,
    )

    return X_train, X_test, y_train, y_test, X, y


def train_baseline_random_forest():
    """Train baseline RandomForest, print metrics, and save model."""
    X_train, X_test, y_train, y_test, X_full, y_full = load_and_prepare_data()

    # Create model
    model = RandomForestClassifier(
        n_estimators=100,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1,
    )

    # Train on training data
    model.fit(X_train, y_train)

    # Predictions
    y_pred = model.predict(X_test)
    y_proba = model.predict_proba(X_test)[:, 1]

    # Metrics
    acc = accuracy_score(y_test, y_pred)
    roc = roc_auc_score(y_test, y_proba)
    cm = confusion_matrix(y_test, y_pred)
    report = classification_report(y_test, y_pred)

    print("=== Baseline RandomForest ===")
    print(f"Accuracy:  {acc:.4f}")
    print(f"ROC-AUC:   {roc:.4f}")
    print("Confusion Matrix:\n", cm)
    print("\nClassification Report:\n", report)

    # Cross-validation on the full dataset
    scores = cross_val_score(model, X_full, y_full, cv=5, scoring="accuracy")
    print("Cross-val Accuracy scores:", scores)
    print("Mean cross-val Accuracy:  ", scores.mean())

    # Save model
    model_path = "rf_model.sav"
    joblib.dump(model, model_path)
    print(f"\nModel saved to: {model_path}")

    # Return what you might want to reuse in Streamlit
    return {
        "model": model,
        "X_train": X_train,
        "X_test": X_test,
        "y_train": y_train,
        "y_test": y_test,
        "y_pred": y_pred,
        "y_proba": y_proba,
        "accuracy": acc,
        "roc_auc": roc,
        "confusion_matrix": cm,
        "classification_report": report,
        "cv_scores": scores,
    }


if __name__ == "__main__":
    train_baseline_random_forest()
