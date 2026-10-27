#!/usr/bin/env python3
"""E7 · S07 — Pruebas de integración: API REST + motor + auth.
Ejecutar: python3 -m unittest discover -s tests -v
"""
import sys
import unittest
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import backend.api as api  # noqa: E402
import backend.auth as auth  # noqa: E402

PORT = 8765
BASE = f"http://127.0.0.1:{PORT}"


class TestIntegracionAPI(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = api.main(PORT)
        cls.srv_url = BASE

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def test_01_health(self):
        r = requests.get(f"{BASE}/api/health", timeout=5)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["status"], "ok")

    def test_02_analyze_critica(self):
        r = requests.post(f"{BASE}/api/analyze",
                          json={"url": "http://192.168.0.1/banco-seguro-login@fake.com/verify"},
                          timeout=5)
        self.assertEqual(r.status_code, 200)
        d = r.json()
        self.assertEqual(d["nivel"], "critica")
        self.assertEqual(d["score"], 70)
        self.assertTrue(d["razones"])

    def test_03_analyze_segura(self):
        r = requests.post(f"{BASE}/api/analyze", json={"url": "https://google.com"}, timeout=5)
        d = r.json()
        self.assertEqual((d["nivel"], d["score"]), ("segura", 0))
        self.assertEqual(d["razones"], [])

    def test_04_analyze_url_sin_esquema(self):
        r = requests.post(f"{BASE}/api/analyze", json={"url": "banco-seguro.com"}, timeout=5)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["nivel"], "sospechosa")

    def test_05_analyze_requiere_url(self):
        r = requests.post(f"{BASE}/api/analyze", json={}, timeout=5)
        self.assertEqual(r.status_code, 400)

    def test_06_login_rbac_historial(self):
        # usuario demo (creado una vez)
        if "itest" not in [u["usuario"] for u in auth.auditoria("crear_usuario", 1000)]:
            auth.crear_usuario("itest", "Clave123!", "analista")
        r = requests.post(f"{BASE}/api/login",
                          json={"usuario": "itest", "password": "Clave123!"}, timeout=5)
        self.assertEqual(r.status_code, 200)
        token = r.json()["token"]
        headers = {"Authorization": f"Bearer {token}"}
        # analiza y luego consulta historial
        requests.post(f"{BASE}/api/analyze", json={"url": "http://1.2.3.4/login@x.com"},
                      headers=headers, timeout=5)
        h = requests.get(f"{BASE}/api/historial", headers=headers, timeout=5).json()
        self.assertTrue(any(i["url"].startswith("http://1.2.3.4") for i in h["historial"]))
        # rol analista NO ve auditoría
        a = requests.get(f"{BASE}/api/auditoria", headers=headers, timeout=5)
        self.assertEqual(a.status_code, 403)

    def test_07_login_invalido(self):
        r = requests.post(f"{BASE}/api/login",
                          json={"usuario": "noexiste", "password": "x"}, timeout=5)
        self.assertEqual(r.status_code, 401)

    def test_08_historial_sin_token(self):
        r = requests.get(f"{BASE}/api/historial", timeout=5)
        self.assertEqual(r.status_code, 401)


if __name__ == "__main__":
    unittest.main(verbosity=2)
