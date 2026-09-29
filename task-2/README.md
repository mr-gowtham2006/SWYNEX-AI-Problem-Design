# SWYNEX Task 2 — Model or API Integration

## AI-Based Spam Message Detection System

This project is developed as part of Task 2 of the SWYNEX Technologies Artificial Intelligence Internship.

The objective of this task is to integrate a machine learning model into a working prototype that classifies SMS messages as **Spam** or **Not Spam** and provides a confidence score.

---

## 1. Objective

The goal of this task is to build and integrate an NLP-based machine learning model for SMS spam detection.

The prototype accepts a text message as input and produces:

- Spam or Not Spam prediction
- Model confidence score

---

## 2. Technology Used

- **Programming Language:** Python
- **Machine Learning Library:** Scikit-learn
- **NLP Feature Extraction:** TF-IDF
- **Classification Algorithm:** Logistic Regression
- **Dataset:** UCI SMS Spam Collection
- **Model Serialization:** Joblib

---

## 3. System Workflow

```text
User enters SMS
       ↓
Text preprocessing
       ↓
TF-IDF feature extraction
       ↓
Logistic Regression
       ↓
Spam / Not Spam
       ↓
Confidence Score
