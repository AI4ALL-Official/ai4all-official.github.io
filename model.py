import pandas as pd
import os
import joblib

from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    roc_auc_score,
    confusion_matrix,
)
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline as Pipeline
from sklearn.preprocessing import StandardScaler

from imblearn.over_sampling import SMOTE
from imblearn.pipeline import Pipeline as Pipeline




#-----------
# LOADING THE DATA
#------------

filename = 'Credit Card Defaulter Prediction.csv'
if not os.path.exists(filename):
  print("File not found. Please refer to the specifications and download the correct file.")
  exit()

#-----------
# CLEANING AND PREPARING DATA
#------------

df = pd.read_csv('Credit Card Defaulter Prediction.csv')
print(df.head())

print(df.describe())

print(df.info())

#Drop ID so that the model does not memorize IDs 
df.drop(['ID'],axis=1,inplace=True)

print(df['MARRIAGE'].value_counts())
print(df['EDUCATION'].value_counts())

print(df.columns)
#-----------
# define X and y
#------------

#Change Y and N to 1 and 0 
target = 'default '
df[target] = df[target].map({'N':0,'Y':1})
print("the default value counts:",df[target].value_counts())

#remove default column to split data 
X = df.drop(target,axis=1)
y = df[target]
print(y.head())


#Ensure all X variables are numbers 
X = pd.get_dummies(X, drop_first=True)
print(X.dtypes)


#-----------
# MODEL 
#------------

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)


# instance of RandomForestClassifier model 
model = RandomForestClassifier(n_estimators=100, class_weight='balanced', random_state=42, )

#Fit the model for training
model.fit(X_train, y_train)

#-----------
# TESTING
#------------

y_proba = model.predict_proba(X_test)[:, 1]  # probability of default



#Predict on test set
y_pred = model.predict(X_test)


# calculate accuracy
accuracy = accuracy_score(y_test, y_pred)
print(f"Accuracy: {accuracy}") #Accuracy rate: 0.8156666666666667
# calculate ROC-AUC
roc_auc = roc_auc_score(y_test, y_proba)
print(f"ROC-AUC: {roc_auc}")  #ROC-AUC: 0.7597928648131913

# save the model to disk
joblib.dump(model, "rf_model.sav")

print("\nDetailed Report:\n", classification_report(y_test, y_pred))
#[TP/FP/FN/TN]
print("Confusion Matrix:\n", confusion_matrix(y_test, y_pred))


# Splits the data 5 different ways and averages the result to confirm accuracy
scores = cross_val_score(model, X, y, cv=5, scoring='accuracy')
print("Scores for each run:", scores)
print("True Average Accuracy:", scores.mean())  
#Scores for each run: [0.80466667 0.80866667 0.81666667 0.82783333 0.8195]
#True Average Accuracy: 0.8154666666666666

#-----------
# Analysis
#------------
analysis_df = df.copy()

# Use explicit lists so we don't mix PAY_ and PAY_AMT
status_cols = ['PAY_0', 'PAY_2', 'PAY_3', 'PAY_4', 'PAY_5', 'PAY_6']
bill_cols   = ['BILL_AMT1', 'BILL_AMT2', 'BILL_AMT3', 'BILL_AMT4', 'BILL_AMT5', 'BILL_AMT6']

pay_cols    = ['PAY_AMT1', 'PAY_AMT2', 'PAY_AMT3', 'PAY_AMT4', 'PAY_AMT5', 'PAY_AMT6']

# --- KPIs ---
analysis_df['avg_bill'] = analysis_df[bill_cols].mean(axis=1)
analysis_df['avg_pay'] = analysis_df[pay_cols].mean(axis=1)
#the utilization rate: avg bill amount / credit limit, how much of their credit line they typically use
analysis_df['avg_utilization'] = analysis_df['avg_bill'] / (analysis_df['LIMIT_BAL'] + 1e-6)

analysis_df['num_late_months'] = (analysis_df[status_cols] > 0).sum(axis=1)
analysis_df['max_delay'] = analysis_df[status_cols].max(axis=1)

analysis_df['pay_bill_ratio'] = analysis_df['avg_pay'] / (analysis_df['avg_bill'].abs() + 1e-6)
# Cap extreme ratios so they don't blow up averages
analysis_df['pay_bill_ratio'] = analysis_df['pay_bill_ratio'].clip(0, 5)

# Now use these ONLY to summarize patterns, not as model inputs.
# Compare KPI averages between defaulters and non-defaulters
group_means = analysis_df.groupby(target)[
    ['avg_utilization', 'num_late_months', 'max_delay', 'pay_bill_ratio']
].mean()

print(group_means)

#-----------
# linear regression model experiment
#------------

log_reg = Pipeline([
    ('scaler', StandardScaler(with_mean=False)),  # handles sparse get_dummies
    ('clf', LogisticRegression(max_iter=1000))
])

log_reg.fit(X_train, y_train)
y_pred_log = log_reg.predict(X_test)
y_proba_log = log_reg.predict_proba(X_test)[:, 1]
# save the model to disk
joblib.dump(log_reg, "log_reg_model.sav")
print("=== Logistic Regression baseline ===")
print("Accuracy:", accuracy_score(y_test, y_pred_log))
print("ROC-AUC:", roc_auc_score(y_test, y_proba_log))
print("Confusion Matrix:\n", confusion_matrix(y_test, y_pred_log))
print(classification_report(y_test, y_pred_log))
#-----------
# SMOTE MODEL
#------------
smote = SMOTE(random_state=42)
rf = RandomForestClassifier(
    n_estimators=100,
    random_state=42,
    n_jobs=-1
)

pipe = Pipeline([
    ('smote', smote),
    ('rf', rf)
])

pipe.fit(X_train, y_train)
y_pred_sm = pipe.predict(X_test)
y_proba_sm = pipe.predict_proba(X_test)[:, 1]
# save the model to disk
joblib.dump(pipe, "smote_rf_model.sav")

print("=== SMOTE + RandomForest ===")
print("Accuracy:", accuracy_score(y_test, y_pred_sm))
print("ROC-AUC:", roc_auc_score(y_test, y_proba_sm))
print("Confusion Matrix:\n", confusion_matrix(y_test, y_pred_sm))
print(classification_report(y_test, y_pred_sm))
