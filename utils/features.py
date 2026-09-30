import pandas as pd
import numpy as np

def extract_features(df):
    """
    Engineers features for ML model.
    Input df columns (minimal): packets_per_sec, bytes_per_sec, flow_count
    Returns: DataFrame with ['pps_mean', 'pps_std', 'ip_entropy', 'flow_density']
    
    Note: For single-row prediction (real-time), we might need to handle aggregation differently 
    or expect the input to be pre-aggregated. 
    Here we implement a version that expects a window of data or calculates row-wise features 
    if strictly per-row prediction is needed (though simple scaling is often better for row-wise).
    
    Given the user requirement: "pps_mean, pps_std, ip_entropy, flow_density"
    These imply aggregation over a window. 
    """
    
    # For training (batch processing)
    # We will assume each row is a 'sample' representing a time window (e.g. 5s) 
    # as generated in data_generator.py.
    # So 'packets_per_sec' in the raw CSV *is* the mean PPS for that window.
    
    # However, to strictly follow the "return pps_mean, pps_std..." requirement:
    # If the input is a single row (live traffic snapshot), we map direct columns.
    # If the input is raw packet logs, we would aggregate.
    
    # Let's create derived features based on the available columns.
    features = pd.DataFrame()
    
    # 1. pps_mean: In our pre-aggregated data, 'packets_per_sec' acts as this.
    features['pps_mean'] = df['packets_per_sec']
    
    # 2. pps_std: Hard to get from a single row value. 
    # We'll calculate a rolling standard deviation if multiple rows, else 0.
    if len(df) > 1:
        features['pps_std'] = df['packets_per_sec'].rolling(window=5, min_periods=1).std().fillna(0)
    else:
        features['pps_std'] = 0 # Default for single prediction if no history
        
    # 3. ip_entropy: Flow count is a proxy for diversity.
    # Added safety check for log
    features['ip_entropy'] = np.log1p(df['flow_count'].clip(lower=0))
    
    # 4. flow_density: defined as packets / flows
    features['flow_density'] = df['packets_per_sec'] / (df['flow_count'].replace(0, 1))

    # 5. bytes_per_packet: Useful indicators for certain attacks (e.g. small packets vs large)
    features['bytes_per_packet'] = df['bytes_per_sec'] / (df['packets_per_sec'].replace(0, 1))
    
    return features.fillna(0)
