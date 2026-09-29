# Task 3 — Intelligent SMS Spam Analysis

## 1. Objective

The objective of Task 3 is to improve the SMS spam detection prototype by adding an intelligent analysis layer, error handling, evaluation examples, and failure-case handling.

The system builds on the machine learning model developed in Task 2.

---

## 2. Intelligent Feature

The Task 3 prototype provides:

- Spam / Not Spam prediction
- Model confidence score
- Risk level
- Suspicious indicator detection
- Explanation of the prediction
- Input validation
- Error handling

### Workflow

```text
SMS Message
     ↓
TF-IDF + Logistic Regression Model
     ↓
Spam / Not Spam
     ↓
Confidence Score
     ↓
Intelligent Analysis
     ↓
Risk Level + Suspicious Indicators + Explanation
