import numpy as np
import pandas as pd
from sklearn.preprocessing import LabelEncoder

def clean_features(df, features):
    """Clean and validate features for ML model input."""
    # Ensure ALL expected features exist (fill missing with 0)
    for f in features:
        if f not in df.columns:
            df[f] = 0.0
    
    # Select ONLY the expected features in the correct order (by name, not index)
    X = df[features].copy()
    X = X.replace([np.inf, -np.inf], np.nan)
    X = X.fillna(0)
    X = X.clip(-1e9, 1e9)
    
    # Debug: log shape for model input validation
    print(f"[DEBUG] clean_features output shape: {X.shape} (expected {len(features)} columns)")
    
    return X.astype(np.float32)

def prepare_data_for_prediction(df, features):
    """
    Bulletproof universal wrapper for handling dirty raw CSV data.
    """
    # 1. Broad Case-Insensitive Mapping
    col_map = {
        'src_ip': 'IPV4_SRC_ADDR', 'source': 'IPV4_SRC_ADDR', 'source_ip': 'IPV4_SRC_ADDR',
        'dst_ip': 'IPV4_DST_ADDR', 'destination': 'IPV4_DST_ADDR', 'destination_ip': 'IPV4_DST_ADDR',
        'proto': 'PROTOCOL', 'protocol_type': 'PROTOCOL', 'protocol': 'PROTOCOL',
        'duration': 'FLOW_DURATION_MILLISECONDS', 'flow_duration': 'FLOW_DURATION_MILLISECONDS',
        'src_port': 'L4_SRC_PORT', 'dst_port': 'L4_DST_PORT'
    }
    df.rename(columns=lambda x: col_map.get(str(x).lower().strip(), x), inplace=True)
    
    # 2. Logging metadata safety
    if 'IPV4_SRC_ADDR' not in df.columns: df['IPV4_SRC_ADDR'] = 'Unknown'
    if 'IPV4_DST_ADDR' not in df.columns: df['IPV4_DST_ADDR'] = 'Unknown'
    
    # 3. Create missing mandatory ML features
    for f in features:
        if f not in df.columns:
            df[f] = 0.0

    # 4. Enforce Numeric Conversion (strips string crashes to 0)
    for col in features:
        df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0)
        
    return df

def encode_multiclass(labels):
    encoder = LabelEncoder()
    y = encoder.fit_transform(labels)
    return y, encoder