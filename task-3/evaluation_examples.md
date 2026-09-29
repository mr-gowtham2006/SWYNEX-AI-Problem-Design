# Task 3 — Evaluation Examples and Failure Cases

## 1. Purpose

The intelligent SMS analyzer was tested using different types of messages to evaluate its classification, confidence score, risk level, and suspicious indicators.

---

## 2. Evaluation Examples

### Example 1 — Clear Spam

**Input:**

> Congratulations! You have won a free cash prize. Click here to claim now!

**Expected Behavior:**

```text
Prediction : SPAM
Risk Level : HIGH
