import os
import joblib
import pandas as pd
import streamlit as st

import matplotlib.pyplot as plt
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    roc_auc_score,
    confusion_matrix,
    roc_curve,
)

# -------------------------
# APP LAYOUT
# -------------------------

st.title("Fair Credit Card Default Prediction (No Demographics)")
st.write(
    "This app trains a Random Forest classifier on the credit card default dataset, "
    "removing demographic features (SEX, EDUCATION, MARRIAGE, AGE) to improve fairness."
)

# -------------------------
# DATA LOADING
# -------------------------

st.sidebar.header("Data Settings")

default_filename = "Credit Card Defaulter Prediction.csv"
use_uploaded = st.sidebar.checkbox("Upload CSV instead of using local file")

if use_uploaded:
    uploaded_file = st.sidebar.file_uploader("Upload CSV file", type=["csv"])
    if uploaded_file is not None:
        df = pd.read_csv(uploaded_file)
    else:
        st.stop()
else:
    if not os.path.exists(default_filename):
        st.error(
            f"File `{default_filename}` not found. "
            f"Place it in the same folder or upload a CSV using the sidebar."
        )
        st.stop()
    df = pd.read_csv(default_filename)

st.subheader("Raw Data (first 5 rows)")
st.dataframe(df.head())

st.write("**Data Summary**")
st.write(df.describe(include="all"))

# -------------------------
# CLEANING / TARGET
# -------------------------

# Drop ID so that the model does not memorize IDs
if "ID" in df.columns:
    df = df.drop(["ID"], axis=1)

target = "default "  # note the space to match your original script
if target not in df.columns:
    st.error(f"Target column `{target}` not found in data.")
    st.stop()

# Change Y and N to 1 and 0
df[target] = df[target].map({"N": 0, "Y": 1})

st.write("**Target value counts (after mapping N→0, Y→1):**")
st.bar_chart(df[target].value_counts())

# -------------------------
# FAIRNESS: DROP DEMOGRAPHICS
# -------------------------

sens_cols = ["SEX", "EDUCATION", "MARRIAGE", "AGE"]
present_sens_cols = [c for c in sens_cols if c in df.columns]

st.subheader("Fairness Setup")
st.write(
    "We **remove** the following sensitive / demographic columns before training "
    "to reduce direct dependence on them:"
)
st.write(present_sens_cols if present_sens_cols else "None of the listed sensitive columns are in the dataset.")

df_fair = df.drop(columns=present_sens_cols, errors="ignore")

X_fair = df_fair.drop(columns=[target])
y_fair = df[target]

# -------------------------
# TRAIN / TEST SPLIT & MODEL
# -------------------------

test_size = st.sidebar.slider("Test size (fraction)", 0.1, 0.4, 0.2, 0.05)
random_state = st.sidebar.number_input("Random state", value=42, step=1)

X_train_f, X_test_f, y_train_f, y_test_f = train_test_split(
    X_fair,
    y_fair,
    test_size=test_size,
    random_state=random_state,
    stratify=y_fair,
)

st.write("**Feature count (after removing sensitive columns):**", X_fair.shape[1])

n_estimators = st.sidebar.slider("Number of trees (n_estimators)", 50, 300, 100, 10)

rf_fair = RandomForestClassifier(
    n_estimators=n_estimators,
    class_weight="balanced",
    random_state=random_state,
    n_jobs=-1,
)

if st.button("Train Fair Model"):
    rf_fair.fit(X_train_f, y_train_f)

    y_pred_f = rf_fair.predict(X_test_f)
    y_proba_f = rf_fair.predict_proba(X_test_f)[:, 1]

    # Save model
    joblib.dump(rf_fair, "fair_rf_model.sav")

    st.success("Model trained and saved as `fair_rf_model.sav`.")

    # -------------------------
    # METRICS
    # -------------------------

    st.subheader("Metrics")

    acc = accuracy_score(y_test_f, y_pred_f)
    roc = roc_auc_score(y_test_f, y_proba_f)
    cm = confusion_matrix(y_test_f, y_pred_f)

    st.write(f"**Accuracy:** {acc:.4f}")
    st.write(f"**ROC-AUC:** {roc:.4f}")

    st.write("**Classification Report:**")
    st.text(classification_report(y_test_f, y_pred_f))

    # -------------------------
    # VISUAL 1: CONFUSION MATRIX
    # -------------------------

    st.subheader("Confusion Matrix")

    fig_cm, ax_cm = plt.subplots()
    ax_cm.imshow(cm, interpolation="nearest")
    ax_cm.set_title("Confusion Matrix")
    ax_cm.set_xlabel("Predicted label")
    ax_cm.set_ylabel("True label")

    tick_marks = [0, 1]
    ax_cm.set_xticks(tick_marks)
    ax_cm.set_yticks(tick_marks)
    ax_cm.set_xticklabels(["No Default (0)", "Default (1)"])
    ax_cm.set_yticklabels(["No Default (0)", "Default (1)"])

    # Label each cell
    for i in range(cm.shape[0]):
        for j in range(cm.shape[1]):
            ax_cm.text(
                j,
                i,
                cm[i, j],
                ha="center",
                va="center",
            )

    st.pyplot(fig_cm)

    # -------------------------
    # VISUAL 2: ROC CURVE
    # -------------------------

    st.subheader("ROC Curve")

    fpr, tpr, thresholds = roc_curve(y_test_f, y_proba_f)

    fig_roc, ax_roc = plt.subplots()
    ax_roc.plot(fpr, tpr, label=f"ROC curve (AUC = {roc:.2f})")
    ax_roc.plot([0, 1], [0, 1], linestyle="--", label="Random")
    ax_roc.set_xlabel("False Positive Rate")
    ax_roc.set_ylabel("True Positive Rate")
    ax_roc.set_title("ROC Curve")
    ax_roc.legend(loc="lower right")

    st.pyplot(fig_roc)

    # -------------------------
    # VISUAL 3: FEATURE IMPORTANCE
    # -------------------------

    st.subheader("Feature Importances (Fair Model)")

    importances = rf_fair.feature_importances_
    feat_names = X_fair.columns

    # Sort by importance
    sorted_idx = importances.argsort()[::-1]
    sorted_importances = importances[sorted_idx]
    sorted_names = feat_names[sorted_idx]

    fig_imp, ax_imp = plt.subplots(figsize=(8, 5))
    ax_imp.bar(range(len(sorted_importances)), sorted_importances)
    ax_imp.set_xticks(range(len(sorted_importances)))
    ax_imp.set_xticklabels(sorted_names, rotation=90)
    ax_imp.set_ylabel("Importance")
    ax_imp.set_title("Random Forest Feature Importances")

    plt.tight_layout()
    st.pyplot(fig_imp)

else:
    st.info("Click **Train Fair Model** to fit the model and see graphs.")
