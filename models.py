import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.svm import SVC
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, precision_recall_fscore_support
# pyrefly: ignore [missing-import]
import joblib
import os
from utils.features import extract_features

class DDoSDetector:
    def __init__(self):
        self.models = {
            'rf': RandomForestClassifier(n_estimators=100, random_state=42),
            'dt': DecisionTreeClassifier(random_state=42),
            'lr': LogisticRegression(max_iter=1000, random_state=42),
            'svm': SVC(probability=True, random_state=42)
        }
        self.model_files = {
            'rf': 'ddos_model_rf.pkl',
            'dt': 'ddos_model_dt.pkl',
            'lr': 'ddos_model_lr.pkl',
            'svm': 'ddos_model_svm.pkl'
        }
        self.active_model_name = 'rf'
        
        # Mappings for multi-class classification
        self.class_mappings = {
            0: "Normal",
            1: "DDoS SYN Flood",
            2: "DDoS UDP Flood",
            3: "DDoS HTTP Flood",
            4: "DDoS DNS Amplification"
        }

    def train(self, data_path='data/sample_ddos.csv'):
        """
        Trains all 4 machine learning models on the provided CSV data.
        Returns a dictionary of benchmarking metrics for UI visualization.
        """
        if not os.path.exists(data_path):
            print(f"Error: Data file {data_path} not found.")
            return {}
            
        print(f"Loading training data from {data_path}...")
        df = pd.read_csv(data_path)
        
        # Extract features and targets
        X = extract_features(df)
        y = df['label']
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
        
        metrics_summary = {}
        
        for name, clf in self.models.items():
            print(f"Training {name.upper()} Classifier...")
            clf.fit(X_train, y_train)
            
            # Predict on test set
            y_pred = clf.predict(X_test)
            
            # Calculate metrics
            acc = accuracy_score(y_test, y_pred)
            precision, recall, f1, _ = precision_recall_fscore_support(y_test, y_pred, average='weighted', zero_division=0)
            
            # Create confusion matrix
            cm = confusion_matrix(y_test, y_pred)
            # Convert NumPy structures to standard Python formats for JSON serialization
            cm_list = [[int(val) for val in row] for row in cm]
            
            metrics_summary[name] = {
                'accuracy': float(acc),
                'precision': float(precision),
                'recall': float(recall),
                'f1_score': float(f1),
                'confusion_matrix': cm_list
            }
            
            # Save the trained model file
            self.save_model(name)
            
        print("Training complete! All models trained and serialized.")
        return metrics_summary

    def predict_anomaly(self, new_data_dict):
        """
        Predicts threat state on new data using the ACTIVE machine learning model.
        Returns: anomaly_likelihood, threat_level
        """
        active_model = self.models.get(self.active_model_name)
        if not active_model:
            # Fallback loader
            self.load_model(self.active_model_name)
            active_model = self.models.get(self.active_model_name)
            
        # Convert input dictionary to DataFrame
        if isinstance(new_data_dict, dict):
            df = pd.DataFrame([new_data_dict])
        else:
            df = new_data_dict
            
        # Extract features
        X = extract_features(df)
        
        try:
            # Get class probabilities
            probs = active_model.predict_proba(X)[0]
            
            # Determine the class with the highest probability
            pred_class = int(np.argmax(probs))
            prob_value = float(probs[pred_class])
            
            # Calculate total DDoS probability (everything except Normal class)
            anomaly_score = float(1.0 - probs[0])
            
            # Get mapped description
            threat_level = self.class_mappings.get(pred_class, "Unknown")
            
            # If Normal was predicted, keep anomaly score low. Otherwise, reflect the attack intensity
            if pred_class == 0:
                # Anomaly score capped for Normal predictions
                anomaly_score = min(anomaly_score, 0.25)
                threat_level = "Normal"
            
            return anomaly_score, threat_level
            
        except Exception as e:
            print(f"Prediction error for model '{self.active_model_name}': {e}")
            return 0.0, "Model Error"

    def save_model(self, model_name):
        """Saves a specific model to its file path."""
        file_path = self.model_files.get(model_name)
        clf = self.models.get(model_name)
        if file_path and clf:
            joblib.dump(clf, file_path)
            print(f"Model '{model_name.upper()}' saved to {file_path}")

    def load_model(self, model_name):
        """Loads a specific model from its file path."""
        file_path = self.model_files.get(model_name)
        if file_path and os.path.exists(file_path):
            try:
                self.models[model_name] = joblib.load(file_path)
                print(f"Model '{model_name.upper()}' loaded from {file_path}")
            except Exception as e:
                print(f"Error loading model '{model_name}': {e}")
        else:
            print(f"No saved model found for '{model_name}'.")

    def load_all_models(self):
        """Loads all serialized models."""
        for name in self.models.keys():
            self.load_model(name)

    def set_active_model(self, model_name):
        """Sets the active model name for prediction."""
        if model_name in self.models:
            self.active_model_name = model_name
            print(f"Active model switched to '{model_name.upper()}'")
            return True
        return False

if __name__ == "__main__":
    # Test run
    detector = DDoSDetector()
    metrics = detector.train()
    print("Benchmarking Metrics:")
    for m, vals in metrics.items():
        print(f"{m.upper()}: Acc={vals['accuracy']:.4f}, F1={vals['f1_score']:.4f}")
    
    # Test Prediction on a dummy normal and attack sample
    test_normal = {
        'packets_per_sec': 500, 
        'bytes_per_sec': 20000, 
        'flow_count': 10,
        'timestamp': 0, 'src_ip': '192.168.1.1', 'dst_ip': '10.0.0.1'
    }
    prob, status = detector.predict_anomaly(test_normal)
    print(f"Normal Test -> Prob: {prob:.2f}, Status: {status}")
    
    test_syn = {
        'packets_per_sec': 75000, 
        'bytes_per_sec': 4800000, 
        'flow_count': 2200,
        'timestamp': 0, 'src_ip': '185.122.4.9', 'dst_ip': '10.0.0.1'
    }
    prob, status = detector.predict_anomaly(test_syn)
    print(f"SYN Flood Test -> Prob: {prob:.2f}, Status: {status}")

