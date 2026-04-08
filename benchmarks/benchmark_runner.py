import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List
from typing import List, Dict


class BenchmarkRunner:
    def __init__(self, dataset_path: str = "benchmarks/dataset"):
        self.repo_root = Path(__file__).resolve().parents[1]
        self.dataset_path = self.repo_root / dataset_path
        self.results: Dict[str, Any] = {}

    def run_wpa2_benchmark(self, mode="hechos"):
        import tempfile
        import os
        
        wpa2_path = self.dataset_path / "wpa2"
        results = []
        
        for cap_file in wpa2_path.glob("*.cap"):
            expected_file = cap_file.with_suffix(".expected.json")
            if not expected_file.exists():
                continue
                
            with open(expected_file) as f:
                expected = json.load(f)
            
            # Crear archivo temporal con inputs
            with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
                if mode == "hechos":
                    f.write("2\n12\n6\n3\nn\n")
                else:
                    f.write("2\n6\n3\nn\n")
                temp_input = f.name
            
            # Ejecutar con redirección de archivo
            result = subprocess.run(
                f"python3 phantom_brain.py < {temp_input}",
                shell=True,
                capture_output=True,
                text=True,
                cwd='.'
            )
            
            # Limpiar
            os.unlink(temp_input)
            
            # Debug
            print(f"[DEBUG] stdout length: {len(result.stdout)}")
            print(f"[DEBUG] Contains 'Handshake incompleto': {'Handshake incompleto' in result.stdout}")
            
            detected = self._parse_vulnerabilities(result.stdout)
            metrics = self._calculate_metrics(detected, expected["vulnerabilidades_esperadas"])
            
            results.append({
                "file": cap_file.name,
                "mode": mode,
                "return_code": result.returncode,
                "metrics": metrics,
                "detected": detected,
                "expected": expected["vulnerabilidades_esperadas"]
            })
        
        return results

    def _parse_vulnerabilities(self, output: str) -> List[Dict]:
        out_lower = output.lower()
        vulnerabilidades = []
        
        # Buscar Handshake Incompleto (con o sin acento)
        if "handshake incompleto" in out_lower or "handshake incompleto" in out_lower or "3 frame" in out_lower:
            vulnerabilidades.append({
                "tipo": "handshake_incompleto", 
                "nivel": "MEDIO"
            })
        
        # Buscar Handshake Completo
        if "handshake completo: true" in out_lower or "handshake ok" in out_lower or "handshake completo" in out_lower:
            vulnerabilidades.append({
                "tipo": "handshake_completo",
                "nivel": "INFO"
            })
        
        # Buscar PMKID
        if "pmkid" in out_lower:
            vulnerabilidades.append({
                "tipo": "pmkid_detectado",
                "nivel": "ALTO"
            })
        
        # Buscar WPS vulnerable
        if "wps" in out_lower and "vulnerable" in out_lower:
            vulnerabilidades.append({
                "tipo": "wps_vulnerable",
                "nivel": "CRITICO"
            })
        
        # DEBUG: imprimir si encontró algo
        if vulnerabilidades:
            print(f"[DEBUG] Detectadas: {vulnerabilidades}")
        else:
            print(f"[DEBUG] No se detectaron vulnerabilidades en output")
            print(f"[DEBUG] Primeros 500 chars: {output[:500]}")
        
        return vulnerabilidades

    def _calculate_metrics(self, detected: List[Dict[str, Any]], expected: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Calcula precision, recall y f1 usando campo 'tipo'."""
        tipos_detectados = {d.get("tipo") for d in detected if d.get("tipo")}
        tipos_esperados = {e.get("tipo") for e in expected if e.get("tipo")}

        tp = len(tipos_detectados & tipos_esperados)
        fp = len(tipos_detectados - tipos_esperados)
        fn = len(tipos_esperados - tipos_detectados)

        precision = tp / (tp + fp) if (tp + fp) else 0.0
        recall = tp / (tp + fn) if (tp + fn) else 0.0
        f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0

        return {
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1_score": round(f1, 4),
            "falsos_positivos": fp,
            "falsos_negativos": fn,
        }

    def run_all(self) -> None:
        """Ejecuta todos los benchmarks."""
        print("Ejecutando benchmarks WPA2 - Modo Hechos")
        self.results["wpa2_hechos"] = self.run_wpa2_benchmark("hechos")

        print("Ejecutando benchmarks WPA2 - Modo IA")
        self.results["wpa2_ia"] = self.run_wpa2_benchmark("ia")

        results_dir = self.repo_root / "benchmarks" / "results"
        results_dir.mkdir(parents=True, exist_ok=True)

        with open(results_dir / "resultados.json", "w", encoding="utf-8") as f:
            json.dump(self.results, f, indent=2, ensure_ascii=False)

        self._generate_report()

    def _generate_report(self) -> None:
        """Genera reporte markdown basico."""
        report = "# Phantom Brain - Benchmark Results\n\n"
        report += f"- WPA2 Hechos: {len(self.results.get('wpa2_hechos', []))} casos\n"
        report += f"- WPA2 IA: {len(self.results.get('wpa2_ia', []))} casos\n"

        results_dir = self.repo_root / "benchmarks" / "results"
        results_dir.mkdir(parents=True, exist_ok=True)
        with open(results_dir / "resumen.md", "w", encoding="utf-8") as f:
            f.write(report)


if __name__ == "__main__":
    runner = BenchmarkRunner()
    runner.run_all()
