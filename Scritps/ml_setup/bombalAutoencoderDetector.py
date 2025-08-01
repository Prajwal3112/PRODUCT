#!/usr/bin/env python3
"""
David Bombal Style Autoencoder-based Anomaly Detection for IDS Logs
Enhanced with Debug-Friendly Output
"""

import pandas as pd
import numpy as np
import tensorflow as tf
from tensorflow.keras.models import Model
from tensorflow.keras.layers import Input, Dense
from sklearn.preprocessing import StandardScaler
import warnings
import os

warnings.filterwarnings("ignore")


class BombalAutoencoderDetector:
    def __init__(self, threshold_percentile=95):
        self.autoencoder = None
        self.scaler = StandardScaler()
        self.threshold_percentile = threshold_percentile
        self.threshold = None
        self.feature_columns = []
        self.context_fields = [
            "src_ip",
            "dest_ip",
            "src_port",
            "dest_port",
            "flow_bytes_toserver",
            "flow_bytes_toclient",
            "flow_pkts_toserver",
            "flow_pkts_toclient",
            "@timestamp",
        ]

    def engineer_features(self, df):
        df = df.copy()
        print("🔧 Engineering features...")

        allowed_fields = self.context_fields + ["proto", "app_proto"]
        existing_fields = [col for col in allowed_fields if col in df.columns]
        df = df[existing_fields].copy()

        if "@timestamp" in df.columns:
            df["@timestamp"] = pd.to_datetime(df["@timestamp"], errors="coerce")
            df["hour"] = df["@timestamp"].dt.hour
            df["day_of_week"] = df["@timestamp"].dt.dayofweek
            df.drop(columns=["@timestamp"], inplace=True)
        else:
            df["hour"] = 12
            df["day_of_week"] = 3

        for col in ["proto", "app_proto"]:
            if col in df.columns:
                df[col] = df[col].astype(str).astype("category").cat.codes
            else:
                df[col] = 0

        for ip_col in ["src_ip", "dest_ip"]:
            if ip_col in df.columns:
                ip_counts = df[ip_col].value_counts(normalize=True)
                df[f"{ip_col}_freq"] = df[ip_col].map(ip_counts).fillna(0)
                df.drop(columns=[ip_col], inplace=True)

        for port_col in ["src_port", "dest_port"]:
            if port_col in df.columns:
                df[port_col] = pd.to_numeric(df[port_col], errors="coerce").fillna(0)

        for col in [
            "flow_bytes_toserver",
            "flow_bytes_toclient",
            "flow_pkts_toserver",
            "flow_pkts_toclient",
        ]:
            if col in df.columns:
                df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0)
            else:
                df[col] = 0

        df = df.fillna(0)
        self.feature_columns = df.columns.tolist()
        print(f"✅ Feature shape: {df.shape}")
        return df

    def build_autoencoder(self, input_dim):
        input_layer = Input(shape=(input_dim,))
        encoded = Dense(64, activation="relu")(input_layer)
        encoded = Dense(32, activation="relu")(encoded)
        encoded = Dense(16, activation="relu")(encoded)

        decoded = Dense(32, activation="relu")(encoded)
        decoded = Dense(64, activation="relu")(decoded)
        output_layer = Dense(input_dim, activation="linear")(decoded)

        autoencoder = Model(inputs=input_layer, outputs=output_layer)
        autoencoder.compile(optimizer="adam", loss="mse")
        return autoencoder

    def train(self, X):
        print("🚀 Training autoencoder...")
        X_scaled = self.scaler.fit_transform(X)
        self.autoencoder = self.build_autoencoder(X_scaled.shape[1])
        self.autoencoder.fit(
            X_scaled,
            X_scaled,
            epochs=30,
            batch_size=128,
            shuffle=True,
            validation_split=0.1,
            verbose=1,
        )
        reconstructions = self.autoencoder.predict(X_scaled, verbose=0)
        mse = np.mean(np.square(X_scaled - reconstructions), axis=1)
        self.threshold = np.percentile(mse, self.threshold_percentile)
        print(
            f"📉 Autoencoder threshold set at {self.threshold:.5f} (top {100 - self.threshold_percentile}% anomalies)"
        )

    def predict(self, X):
        print("🔎 Predicting anomalies...")
        X_scaled = self.scaler.transform(X)
        reconstructions = self.autoencoder.predict(X_scaled, verbose=0)
        mse = np.mean(np.square(X_scaled - reconstructions), axis=1)

        results = pd.DataFrame(index=X.index)
        results["reconstruction_error"] = mse
        results["is_anomaly"] = mse > self.threshold
        return results

    def run_detection(self, df):
        features_df = self.engineer_features(df)
        self.train(features_df)
        result_flags = self.predict(features_df)

        df_out = df.copy()
        df_out["is_anomaly"] = result_flags["is_anomaly"]

        for uc in [
            "uc1_beaconing",
            "uc2_suspicious_user_agent",
            "uc3_unusual_destinations",
            "uc4_data_exfiltration",
            "uc5_port_scanning",
            "uc6_lateral_movement",
            "uc7_protocol_anomaly",
            "uc8_url_injection",
        ]:
            df_out[uc] = False

        return df_out


if __name__ == "__main__":
    print("📡 Running Bombal Autoencoder Detector")

    sample_file = "ml_results/data/network_raw_data.json"

    # Check if file exists
    if not os.path.exists(sample_file):
        print(f"❌ Sample file not found: {sample_file}")
        print("🔧 Please run fetchNetworkData.py first to generate sample data")
        exit(1)

    df_logs = pd.read_json(sample_file)

    detector = BombalAutoencoderDetector()
    results_df = detector.run_detection(df_logs)

    # Save with context fields (prevent duplicate columns)
    context_fields = [
        "src_ip",
        "dest_ip",
        "src_port",
        "dest_port",
        "flow_bytes_toserver",
        "flow_bytes_toclient",
        "flow_pkts_toserver",
        "flow_pkts_toclient",
        "@timestamp",
    ]

    debug_cols = [col for col in context_fields if col in df_logs.columns]
    duplicate_cols = [col for col in debug_cols if col in results_df.columns]
    debug_cols_filtered = [col for col in debug_cols if col not in duplicate_cols]

    # Combine safely
    results_final = pd.concat(
        [
            df_logs[debug_cols_filtered].reset_index(drop=True),
            results_df.reset_index(drop=True),
        ],
        axis=1,
    )

    # Save final result
    results_final.to_json(
        "ml_results/results/autoencoder_results.json", orient="records", indent=2
    )
    print(
        f"✅ Final results saved with context. Total anomalies: {results_final['is_anomaly'].sum()}"
    )

    # Print top anomalies
    print("\n🔍 Sample Anomalies:")
    debug_display_cols = [
        col
        for col in ["src_ip", "dest_ip", "flow_bytes_toserver", "flow_bytes_toclient"]
        if col in results_final.columns
    ]
    print(results_final[results_final["is_anomaly"]].head(10)[debug_display_cols])
