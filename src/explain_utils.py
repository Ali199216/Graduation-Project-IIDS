import shap
import pandas as pd
import numpy as np
from config import FEATURES, SAMPLED_PATH
from preprocessing import clean_features

def explain_prediction(model, input_data):
    """
    Generate a natural language explanation for a prediction using SHAP.
    Identifies the top 3 features contributing to a Malicious prediction.
    """
    try:
        sample_pool = pd.read_csv(SAMPLED_PATH)
        full_row = {}
        for feat in FEATURES:
            if feat in input_data:
                full_row[feat] = input_data[feat]
            else:
                full_row[feat] = float(sample_pool[feat].median()) if feat in sample_pool.columns else 0
                
        df = pd.DataFrame([full_row])
        X = clean_features(df, FEATURES)
        
        explainer = shap.TreeExplainer(model)
        shap_values = explainer.shap_values(X)
        
        # Determine positive class values
        if isinstance(shap_values, list):
            vals = shap_values[1][0] if len(shap_values) > 1 else shap_values[0][0]
        else:
            if len(shap_values.shape) == 3:
                vals = shap_values[0, :, 1]
            else:
                vals = shap_values[0]
                
        top_indices = np.argsort(vals)[::-1][:3]
        top_features = [FEATURES[i] for i in top_indices if vals[i] > 0]
        
        if top_features:
            explanation = f"Attack detected due to abnormal spikes in {', '.join(top_features)}."
        else:
            explanation = "Attack detected based on combined anomalous payload signatures."
            
        return explanation
    except Exception as e:
        return f"Attack detected based on model heuristics (Explanation unavailable: {str(e)})."
