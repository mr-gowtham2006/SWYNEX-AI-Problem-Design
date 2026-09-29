import os
import zipfile
import urllib.request
import joblib
import pandas as pd

from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    classification_report
)

DATASET_URL = "https://archive.ics.uci.edu/static/public/228/sms+spam+collection.zip"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
MODEL_PATH = os.path.join(BASE_DIR, "spam_classifier.pkl")

os.makedirs(DATA_DIR, exist_ok=True)

ZIP_PATH = os.path.join(DATA_DIR, "sms_spam_collection.zip")
EXTRACT_PATH = os.path.join(DATA_DIR, "sms_spam_collection")
DATASET_FILE = os.path.join(EXTRACT_PATH, "SMSSpamCollection")

print("=" * 60)
print("SWYNEX TASK 2 - SMS SPAM DETECTION")
print("=" * 60)

print("\n[1/6] Downloading UCI SMS Spam Collection...")

if not os.path.exists(DATASET_FILE):
    urllib.request.urlretrieve(DATASET_URL, ZIP_PATH)

    with zipfile.ZipFile(ZIP_PATH, "r") as zip_ref:
        zip_ref.extractall(EXTRACT_PATH)

print("Dataset ready.")

print("\n[2/6] Preparing dataset...")

df = pd.read_csv(
    DATASET_FILE,
    sep="\t",
    header=None,
    names=["label", "message"],
    encoding="utf-8"
)

df["label"] = df["label"].map({
    "ham": 0,
    "spam": 1
})

df = df.dropna()

print("Total messages:", len(df))
print("Not Spam:", (df["label"] == 0).sum())
print("Spam:", (df["label"] == 1).sum())

print("\n[3/6] Splitting dataset...")

X_train, X_test, y_train, y_test = train_test_split(
    df["message"],
    df["label"],
    test_size=0.20,
    random_state=42,
    stratify=df["label"]
)

print("Training messages:", len(X_train))
print("Testing messages:", len(X_test))

print("\n[4/6] Training TF-IDF + Logistic Regression...")

model = Pipeline([
    (
        "tfidf",
        TfidfVectorizer(
            lowercase=True,
            stop_words="english",
            ngram_range=(1, 2),
            max_features=10000,
            sublinear_tf=True
        )
    ),
    (
        "classifier",
        LogisticRegression(
            max_iter=1000,
            random_state=42
        )
    )
])

model.fit(X_train, y_train)

print("Training completed.")

print("\n[5/6] Evaluating model...")

y_pred = model.predict(X_test)

accuracy = accuracy_score(y_test, y_pred)
precision = precision_score(y_test, y_pred)
recall = recall_score(y_test, y_pred)
f1 = f1_score(y_test, y_pred)

print("\nMODEL PERFORMANCE")
print("-" * 40)
print(f"Accuracy : {accuracy * 100:.2f}%")
print(f"Precision: {precision * 100:.2f}%")
print(f"Recall   : {recall * 100:.2f}%")
print(f"F1-Score : {f1 * 100:.2f}%")

print("\nClassification Report:")
print(
    classification_report(
        y_test,
        y_pred,
        target_names=["Not Spam", "Spam"]
    )
)

print("\n[6/6] Saving model...")

joblib.dump(model, MODEL_PATH)

print("Model saved to:")
print(MODEL_PATH)

print("\nTask 2 training completed successfully.")
