import pandas as pd
from config import DATASET_PATH, SAMPLED_PATH

import os

def build_sample(n_benign=50, n_per_attack=10):
    if not os.path.exists(DATASET_PATH):
        print(f"Error: Original dataset not found at {DATASET_PATH}")
        print("Please download it from Kaggle and place it in the data/ folder.")
        print("Note: You already have 'dataset_sample.csv', so you don't need to run this to use the app!")
        return

    df = pd.read_csv(DATASET_PATH)

    benign_df = df[df["Label"] == 0]
    benign_sample = benign_df.sample(
        n=min(n_benign, len(benign_df)),
        random_state=42
    )

    attack_samples = []

    attack_types = df.loc[df["Label"] == 1, "Attack"].unique()

    for attack in attack_types:
        attack_df = df[df["Attack"] == attack]
        sampled = attack_df.sample(
            n=min(n_per_attack, len(attack_df)),
            random_state=42
        )
        attack_samples.append(sampled)

    malicious_sample = pd.concat(attack_samples, ignore_index=True)

    pool = (
        pd.concat([benign_sample, malicious_sample], ignore_index=True)
        .sample(frac=1, random_state=42)
        .reset_index(drop=True)
    )

    pool.to_csv(SAMPLED_PATH, index=False)

    print("Sample pool created")
    print(f"Benign samples: {len(benign_sample)}")
    print(f"Malicious samples: {len(malicious_sample)}")
    print(f"Attack types included: {len(attack_types)}")
    print(f"Saved to: {SAMPLED_PATH}")
    print(f"Final shape: {pool.shape}")

if __name__ == "__main__":
    build_sample(n_benign=50, n_per_attack=10)