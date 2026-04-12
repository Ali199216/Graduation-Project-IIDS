import matplotlib.pyplot as plt
import numpy as np
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    f1_score,
    ConfusionMatrixDisplay
)

def evaluate_model(model, X_test, y_test, model_name="Model", binary=True, encoder=None):
    print(f"\n{'=' * 10}")
    print(f" {model_name} — Evaluation ")
    print(f"{'=' * 10}")

    y_pred = model.predict(X_test)

    cm = confusion_matrix(y_test, y_pred)
    print("\nConfusion Matrix:")
    print(cm)

    if not binary and encoder is not None:
        labels = encoder.classes_
    else:
        labels = ["Benign", "Attack"]
    disp = ConfusionMatrixDisplay(confusion_matrix=cm, display_labels=labels)
    disp.plot(cmap=plt.cm.Blues, xticks_rotation='vertical')
    plt.title(f"{model_name} — Confusion Matrix")
    plt.show()

    print("\nClassification Report:")
    if not binary and encoder is not None:
        target_names = encoder.classes_
        print(classification_report(y_test, y_pred, target_names=target_names, digits=4, zero_division=0))
        f1 = f1_score(y_test, y_pred, average='macro')
        print(f"\nMacro F1 Score: {f1:.4f}")
    else:
        target_names = ["Benign", "Attack"]
        print(classification_report(y_test, y_pred, target_names=target_names, digits=4, zero_division=0))
        f1 = f1_score(y_test, y_pred)
        print(f"\nF1 Score: {f1:.4f}")

    print(f"{'=' * 20}\n")
