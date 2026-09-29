import os
import joblib

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, "spam_classifier.pkl")

model = joblib.load(MODEL_PATH)

print("=" * 50)
print("SWYNEX SMS SPAM DETECTOR")
print("=" * 50)

while True:
    message = input("\nEnter an SMS message (or type 'exit' to stop): ")

    if message.lower() == "exit":
        print("Prediction test completed.")
        break

    prediction = model.predict([message])[0]
    probabilities = model.predict_proba([message])[0]

    confidence = max(probabilities) * 100

    result = "SPAM" if prediction == 1 else "NOT SPAM"

    print("\nPrediction :", result)
    print(f"Confidence : {confidence:.2f}%")
