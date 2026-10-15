"""
=============================================================================
MODUL: models/train_ai.py
PROIECT: Simulator Firewall pentru Retele Industriale (SCADA/ICS DPI Firewall)
DISCIPLINA: Securitatea Sistemelor Informatice (Master)
=============================================================================
DESCRIERE:
    Antreneaza o componenta hibrida de inteligenta artificiala pentru firewall-ul industrial:
      1. Model Supervizat: Random Forest Classifier
         - Clasifica traficul in NORMAL vs ATTACK si identifica tipul exact de atac.
         - Calculeaza importanta caracteristicilor (Feature Importance) pentru explicabilitate.
      2. Model Nesupervizat: Isolation Forest
         - Antrenat exclusiv pe traficul normal (profilul de referinta al retelei SCADA).
         - Detecteaza atacuri noi (Zero-Day) sau devieri comportamentale prin Anomaly Scoring.

    Calculeaza metricile academice de evaluare: Acuratete, Precizie, Recall, F1-Score,
    Matrice de Confuzie si salveaza modelele serializate (.joblib) si metadatele asociate.
=============================================================================
"""

import os
import json
import joblib
import numpy as np
import pandas as pd
from typing import Dict, Any, Tuple
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score
)

# Import local al incarcatorului de date
import sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from data.dataset_generator import load_scada_dataset


FEATURE_COLUMNS = [
    "function_code",
    "register_address",
    "register_value",
    "inter_arrival_time",
    "packet_rate",
    "length",
    "is_write_op",
    "is_known_ip",
    "is_critical_reg"
]


def prepare_features(df: pd.DataFrame) -> Tuple[np.ndarray, np.ndarray, pd.Series]:
    """
    Extrage matricea de trasaturi (X) si vectorul de etichete (y) din dataset.

    Args:
        df (pd.DataFrame): DataFrame-ul complet cu pachete SCADA.

    Returns:
        Tuple[np.ndarray, np.ndarray, pd.Series]: (X_features, y_binary, y_attack_types)
    """
    X = df[FEATURE_COLUMNS].copy()

    # Tratare valori lipsa daca exista
    X = X.fillna(0.0)

    # Eticheta binara: 0 pentru NORMAL, 1 pentru ATTACK
    y_binary = (df["label"] == "ATTACK").astype(int).values
    y_attack_types = df["attack_type"]

    return X.values, y_binary, y_attack_types


def train_models(df: pd.DataFrame) -> Dict[str, Any]:
    """
    Antreneaza atat Random Forest cat si Isolation Forest, evaluandu-le pe un set de test.

    Args:
        df (pd.DataFrame): Dataset-ul complet.

    Returns:
        Dict[str, Any]: Dictionar continand modelele, metricile si metadatele de antrenare.
    """
    X, y, attack_types = prepare_features(df)

    # Impartire Train / Test (80% train, 20% test) stratificat dupa y
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )

    print(f"[*] Set de antrenare: {X_train.shape[0]} pachete")
    print(f"[*] Set de testare:   {X_test.shape[0]} pachete")

    # -------------------------------------------------------------------------
    # 1. Antrenare Random Forest Classifier (Supervizat)
    # -------------------------------------------------------------------------
    print("\n[*] Antrenare Random Forest Classifier...")
    rf_model = RandomForestClassifier(
        n_estimators=100,
        max_depth=12,
        min_samples_split=4,
        random_state=42,
        n_jobs=-1
    )
    rf_model.fit(X_train, y_train)

    y_pred_rf = rf_model.predict(X_test)
    y_pred_proba_rf = rf_model.predict_proba(X_test)[:, 1]

    acc_rf = accuracy_score(y_test, y_pred_rf)
    prec_rf = precision_score(y_test, y_pred_rf, zero_division=0)
    rec_rf = recall_score(y_test, y_pred_rf, zero_division=0)
    f1_rf = f1_score(y_test, y_pred_rf, zero_division=0)
    roc_auc_rf = roc_auc_score(y_test, y_pred_proba_rf)
    cm_rf = confusion_matrix(y_test, y_pred_rf)

    # Calcul importanta trasaturi
    feature_importances = dict(zip(FEATURE_COLUMNS, [round(float(v), 4) for v in rf_model.feature_importances_]))

    print(f"[+] Random Forest Test Accuracy:  {acc_rf * 100:.2f}%")
    print(f"[+] Random Forest Test Precision: {prec_rf * 100:.2f}%")
    print(f"[+] Random Forest Test Recall:    {rec_rf * 100:.2f}%")
    print(f"[+] Random Forest Test F1-Score:  {f1_rf * 100:.2f}%")
    print(f"[+] Random Forest Test ROC-AUC:   {roc_auc_rf * 100:.2f}%")

    # -------------------------------------------------------------------------
    # 2. Antrenare Isolation Forest (Nesupervizat - Detectie Anomalii / Zero-Day)
    # -------------------------------------------------------------------------
    print("\n[*] Antrenare Isolation Forest pe profilul normal de referinta...")
    # Antrenam doar pe exemple normale din setul de train
    X_train_normal = X_train[y_train == 0]

    iso_model = IsolationForest(
        n_estimators=100,
        contamination=0.03,  # Proportie asteptata de zgomot in traficul normal
        random_state=42,
        n_jobs=-1
    )
    iso_model.fit(X_train_normal)

    # Predictia Isolation Forest returneaza 1 (inlier/normal) si -1 (outlier/anomalie)
    iso_raw_pred = iso_model.predict(X_test)
    y_pred_iso = (iso_raw_pred == -1).astype(int)
    f1_iso = f1_score(y_test, y_pred_iso, zero_division=0)
    acc_iso = accuracy_score(y_test, y_pred_iso)

    print(f"[+] Isolation Forest Test F1-Score: {f1_iso * 100:.2f}%")
    print(f"[+] Isolation Forest Test Accuracy: {acc_iso * 100:.2f}%")

    report = classification_report(y_test, y_pred_rf, target_names=["NORMAL", "ATTACK"])

    results = {
        "rf_model": rf_model,
        "iso_model": iso_model,
        "feature_columns": FEATURE_COLUMNS,
        "metrics": {
            "accuracy": round(float(acc_rf), 4),
            "precision": round(float(prec_rf), 4),
            "recall": round(float(rec_rf), 4),
            "f1_score": round(float(f1_rf), 4),
            "roc_auc": round(float(roc_auc_rf), 4),
            "confusion_matrix": cm_rf.tolist(),
            "classification_report": report,
            "isolation_forest_accuracy": round(float(acc_iso), 4),
            "isolation_forest_f1": round(float(f1_iso), 4)
        },
        "feature_importances": feature_importances
    }

    return results


def save_models_and_metadata(results: Dict[str, Any], output_dir: str = None) -> Tuple[str, str, str]:
    """
    Salveaza fisierele serializate ale modelelor antrenate si metadatele de performanta.

    Args:
        results (Dict[str, Any]): Rezultatele returnate de train_models.
        output_dir (str, optional): Directorul tinta. Daca este None, foloseste folderul curent 'models'.

    Returns:
        Tuple[str, str, str]: Caile fisierelor salvate (rf_path, iso_path, metadata_path).
    """
    if output_dir is None:
        output_dir = os.path.dirname(os.path.abspath(__file__))

    os.makedirs(output_dir, exist_ok=True)

    rf_path = os.path.join(output_dir, "ics_firewall_rf_model.joblib")
    iso_path = os.path.join(output_dir, "ics_firewall_iso_model.joblib")
    meta_path = os.path.join(output_dir, "model_metadata.json")

    joblib.dump(results["rf_model"], rf_path)
    joblib.dump(results["iso_model"], iso_path)

    metadata = {
        "model_name": "SCADA-Shield Hybrid AI Engine",
        "feature_columns": results["feature_columns"],
        "metrics": results["metrics"],
        "feature_importances": results["feature_importances"]
    }

    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=4)

    return rf_path, iso_path, meta_path


def main():
    """
    Punctul de intrare pentru scriptul de antrenare a inteligentei artificiale.
    """
    print("=" * 70)
    print("  ANTRENARE SUBSISTEM AI PENTRU FIREWALL INDUSTRIAL MODBUS TCP")
    print("=" * 70)

    # 1. Incarcare date
    print("[*] Incarcare dataset industrial...")
    df = load_scada_dataset()
    print(f"[+] Dataset incarcat cu succes. Dimensiune: {df.shape}")

    # 2. Antrenare
    results = train_models(df)

    # 3. Salvare
    rf_path, iso_path, meta_path = save_models_and_metadata(results)
    print("\n[+] Modelele AI au fost salvate cu succes:")
    print(f"    - Random Forest:    {rf_path}")
    print(f"    - Isolation Forest: {iso_path}")
    print(f"    - Metadate & Raport: {meta_path}")

    print("\n[*] Importanta Trasaturilor (Feature Importance):")
    for feat, imp in sorted(results["feature_importances"].items(), key=lambda x: x[1], reverse=True):
        bar = "█" * int(imp * 40)
        print(f"    {feat:<22} : {imp:6.4f}  {bar}")

    print("\n[+] Raport de clasificare detaliat:\n")
    print(results["metrics"]["classification_report"])
    print("=" * 70)


if __name__ == "__main__":
    main()
