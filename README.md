SWYNEX AI Problem Design

Project Title

AI-Based Spam Message Detection System

1. Problem Statement

Users receive many unwanted and potentially fraudulent text messages, making it difficult to manually identify spam. The proposed AI system will analyze the content of a text message and classify it as either Spam or Not Spam using Natural Language Processing (NLP).

The goal is to provide a simple and fast system that helps users identify potentially unwanted messages.

2. Target Users

General mobile users

Students

People who frequently receive SMS or text messages

3. Input

The system accepts a text message from the user.

Example:

Congratulations! You have won a cash prize. Click here to claim.

4. Output

The system will provide a classification and confidence score.

Example:

Prediction: SPAM
Confidence: 96%

For a legitimate message:

Prediction: NOT SPAM
Confidence: 98%

5. Data Source

The project will use the publicly available SMS Spam Collection Dataset from the UCI Machine Learning Repository.

Dataset:
https://archive.ics.uci.edu/dataset/228/sms+spam+collection

The dataset contains labeled SMS messages that can be used to train and evaluate a spam classification model.

6. Constraints

The initial system will process text messages only.

The classifier will use two classes: Spam and Not Spam.

The initial prototype will use a publicly available labeled dataset.

The system should return a prediction within a few seconds.

The model must be evaluated using messages that were not used during training.

The system is intended as a classification aid and should not be treated as a definitive determination of fraud.

7. Success Criteria

The system will be considered successful if:

It achieves at least 90% accuracy on the test dataset.

It achieves reasonable precision, recall, and F1-score for spam detection.

It correctly classifies most unseen messages.

It provides a prediction within a few seconds.

It provides an understandable confidence score.

8. Evaluation Approach

The dataset will be divided into training and testing sets.

The model will be evaluated using:

Accuracy

Precision

Recall

F1-score

Confusion Matrix

The test set will contain messages that were not used during model training.

9. Expected AI Workflow

User enters SMS
       ↓
Text preprocessing
       ↓
NLP feature extraction / model
       ↓
Spam classification
       ↓
Prediction + confidence score

10. Future Development

This problem is designed to support the later internship tasks:

Task 2 — Model or API Integration

Integrate and test an NLP model or machine-learning classifier for spam detection.

Task 3 — Intelligent Feature

Add features such as confidence scoring, basic prediction explanation, validation, and error handling.

Task 4 — Final AI Application

Develop a beginner-friendly web application where users can enter a message and receive a spam classification.

11. Expected Outcome

The final system will provide a simple interface where a user can enter a text message and receive an AI-based Spam or Not Spam prediction with a confidence score.

Internship: SWYNEX Technologies
Task: Task 1 — AI Problem Design
