#!/usr/bin/env python3
"""E6 · S06 — Pruebas unitarias del motor de inferencia.
Calibra niveles contra los casos E2/S03 y el dataset S04.
Ejecutar: python3 -m unittest discover -s tests -v
"""
import csv
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from engine.motor import MAXIMO, evaluar  # noqa: E402

# Casos de calibración E2 (E2-marco-US03-pesos.md)
CASO_SEGURA = "https://google.com"                                     # 0%
CASO_CRITICA_AT = "http://192.168.0.1/banco-seguro-login@fake.com/verify"  # 70%
CASO_CRITICA_LARGA = ("http://login-secure-update.ejemplo.largo.sub.dominio.com/"
                      "verify/account/update/extra/path/datos/1234567890")  # 57%


class TestCalibracionE2(unittest.TestCase):
    def test_caso_segura_0(self):
        r = evaluar(CASO_SEGURA)
        self.assertEqual((r["nivel"], r["score"]), ("segura", 0))

    def test_caso_critica_arroba_ip_70(self):
        r = evaluar(CASO_CRITICA_AT)
        self.assertEqual(r["nivel"], "critica")
        self.assertEqual(r["score"], 70)  # (5+3+3+5)/23 = 70

    def test_caso_critica_larga_57(self):
        r = evaluar(CASO_CRITICA_LARGA)
        self.assertEqual(r["nivel"], "critica")
        self.assertEqual(r["score"], 57)  # (2+2+3+3+3)/23 = 57

    def test_suma_maxima_23(self):
        for url in (CASO_SEGURA, CASO_CRITICA_AT, CASO_CRITICA_LARGA):
            self.assertLessEqual(evaluar(url)["suma"], MAXIMO)

    def test_alerta_ip_minimo_sospechosa(self):
        # regla: SI ip O arroba ENTONCES minimo sospechosa
        r = evaluar("http://8.8.8.8/x")
        self.assertEqual(r["hits"], ["ip", "sin_https"])
        self.assertEqual(r["nivel"], "sospechosa")  # score bajo pero alerta

    def test_orden_niveles(self):
        # segura debe ser estrictamente menor que cualquier caso crítico
        s = evaluar(CASO_SEGURA)["score"]
        self.assertLess(s, evaluar(CASO_CRITICA_LARGA)["score"])
        self.assertLess(s, evaluar(CASO_CRITICA_AT)["score"])


class TestDatasetS04(unittest.TestCase):
    """Calibración contra dataset_normalizado.csv (E3)."""

    @classmethod
    def setUpClass(cls):
        path = ROOT / "dataset" / "dataset_normalizado.csv"
        cls.filas = list(csv.DictReader(path.open(encoding="utf-8")))

    def test_dataset_presente(self):
        self.assertGreaterEqual(len(self.filas), 50)

    def test_legitimas_seguras(self):
        falsos_positivos = [f["url"] for f in self.filas
                            if f["label"] == "legitima" and evaluar(f["url"])["nivel"] != "segura"]
        self.assertEqual(falsos_positivos, [], f"FP: {falsos_positivos}")

    def test_phishing_detectados(self):
        perdidos = [f["url"] for f in self.filas
                    if f["label"] == "phishing" and evaluar(f["url"])["nivel"] == "segura"]
        phishing = [f for f in self.filas if f["label"] == "phishing"]
        recall = 1 - len(perdidos) / max(1, len(phishing))
        # Límites documentados en E2-US01: acortador (estructura oculta) y
        # typosquatting sin guion requieren reputación externa (S07/US02).
        limites = {"https://bit.ly/3xK9fQm", "https://g00gle.com.mx/secure/account"}
        self.assertEqual(set(perdidos), limites,
                         f"FN fuera de los límites documentados: {perdidos}")
        self.assertGreaterEqual(recall, 0.90)

    def test_features_concordan_con_motor(self):
        # la extracción S04 y el motor S06 deben detectar lo mismo
        for f in self.filas:
            hits = evaluar(f["url"])["hits"]
            self.assertEqual(f["ip"], str(int("ip" in hits)), f["url"])
            self.assertEqual(f["larga"], str(int("larga" in hits)), f["url"])
            self.assertEqual(f["arroba"], str(int("arroba" in hits)), f["url"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
