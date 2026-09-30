import os
import re
import joblib

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, "..", "task-2", "spam_classifier.pkl")

try:
    model = joblib.load(MODEL_PATH)
except FileNotFoundError:
    raise FileNotFoundError(
        "Trained model not found. Make sure task-2/spam_classifier.pkl exists."
    )

SUSPICIOUS_PATTERNS = {
    "Prize or reward language": [
        "won", "winner", "prize", "reward", "cash", "lottery"
    ],
    "Urgency language": [ 
        "urgent", "immediately", "act now", "hurry", "limited time"
    ],
    "Financial language": [
        "money", "cash", "payment", "bank", "credit", "loan"
    ],
    "Promotional language": [
        "free", "offer", "discount", "bonus", "claim"
    ],
    "Call-to-action language": [
        "click", "call now", "click here", "reply now", "claim now"
    ]
}


def analyze_message(message):
    if not isinstance(message, str):
        return {
            "error": "Invalid input. Please enter a text message."
        }

    message = message.strip()

    if not message:
        return {
            "error": "Message cannot be empty. Please enter an SMS message."
        }

    if len(message) > 5000:
        return {
            "error": "Message is too long. Please enter a message below 5000 characters."
        }

    try:
        prediction = model.predict([message])[0]
        probabilities = model.predict_proba([message])[0]

        confidence = max(probabilities) * 100

        result = "SPAM" if prediction == 1 else "NOT SPAM"

        indicators = []

        message_lower = message.lower()

        for category, keywords in SUSPICIOUS_PATTERNS.items():
            found = [word for word in keywords if word in message_lower]

            if found:
                indicators.append(
                    f"{category}: {', '.join(found)}"
                )

        if re.search(r"https?://|www\.", message_lower):
            indicators.append("Contains a web link")

        if result == "SPAM":
            if confidence >= 85 or len(indicators) >= 3:
               risk_level = "HIGH"
            else:
               risk_level = "MEDIUM"
        elif confidence < 70:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

        if result == "SPAM":
            if indicators:
                explanation = (
                    "The message was classified as spam and contains "
                    "one or more suspicious indicators."
                )
            else:
                explanation = (
                    "The message was classified as spam by the trained "
                    "machine learning model."
                )
        else:
            explanation = (
                "The message was classified as not spam by the trained "
                "machine learning model."
            )

        return {
            "prediction": result,
            "confidence": round(confidence, 2),
            "risk_level": risk_level,
            "indicators": indicators,
            "explanation": explanation
        }

    except Exception as error:
        return {
            "error": f"Unable to analyze the message: {error}"
        }


def display_result(message):
    result = analyze_message(message)

    print("\n" + "=" * 60)

    if "error" in result:
        print("ERROR")
        print(result["error"])
        print("=" * 60)
        return

    print("INTELLIGENT SMS ANALYSIS")
    print("=" * 60)
    print("Message    :", message)
    print("Prediction :", result["prediction"])
    print("Confidence :", f"{result['confidence']:.2f}%")
    print("Risk Level :", result["risk_level"])
    print("Explanation:", result["explanation"])

    if result["indicators"]:
        print("\nSuspicious Indicators:")

        for indicator in result["indicators"]:
            print("-", indicator)
    else:
        print("\nSuspicious Indicators: None detected")

    print("=" * 60)


if __name__ == "__main__":
    print("=" * 60)
    print("SWYNEX TASK 3 - INTELLIGENT SMS ANALYZER")
    print("=" * 60)

    while True:
        message = input("\nEnter an SMS message (or type 'exit' to stop): ")

        if message.lower().strip() == "exit":
            print("Analysis completed.")
            break

        display_result(message)
