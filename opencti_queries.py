#!/usr/bin/env python3
"""
Script para consultar OpenCTI usando pycti (Cliente oficial).
Requiere: pip install -r requirements.txt
"""

from pycti import OpenCTIApiClient
import json
import os
from dotenv import load_dotenv

# Cargar variables de entorno desde .env
load_dotenv()

# Configuración
OPENCTI_URL = os.getenv("OPENCTI_URL", "http://localhost:8080")
OPENCTI_TOKEN = os.getenv("OPENCTI_TOKEN", "")

print(f"🔌 Intentando conectar a: {OPENCTI_URL}")

if OPENCTI_TOKEN == "PEGAR_TU_TOKEN_REAL_AQUI":
    print("❌ Error: El token en .env sigue siendo el valor de ejemplo. Por favor edítalo con tu token real.")
    exit(1)

if not OPENCTI_TOKEN:
    print("❌ Error: No se encontró OPENCTI_TOKEN en las variables de entorno.")
    exit(1)

# Inicializar cliente
try:
    opencti_api_client = OpenCTIApiClient(OPENCTI_URL, OPENCTI_TOKEN)
except Exception as e:
    print(f"❌ Error al conectar con OpenCTI: {e}")
    exit(1)


def buscar_malware(nombre):
    """Buscar malware por nombre"""
    print(f"\n🦠 Buscando malware: {nombre}")
    print("=" * 60)
    
    malware_list = opencti_api_client.malware.list(
        filters={
            "mode": "and",
            "filters": [{"key": "name", "values": [nombre], "operator": "eq"}],
            "filterGroups": []
        }
    )
    
    for malware in malware_list:
        print(f"\nNombre: {malware.get('name')}")
        print(f"ID: {malware.get('id')}")
        print(f"Descripción: {malware.get('description', 'N/A')[:200]}...")
        print(f"Aliases: {malware.get('aliases', [])}")
        print(f"Creado: {malware.get('created_at')}")
    
    return malware_list


def buscar_actores_amenaza(nombre):
    """Buscar actores de amenaza (Threat Actors)"""
    print(f"\n👤 Buscando actor de amenaza: {nombre}")
    print("=" * 60)
    
    actors = opencti_api_client.threat_actor.list(
        filters={
            "mode": "and",
            "filters": [{"key": "name", "values": [nombre], "operator": "eq"}],
            "filterGroups": []
        }
    )
    
    for actor in actors:
        print(f"\nNombre: {actor.get('name')}")
        print(f"ID: {actor.get('id')}")
        print(f"Descripción: {actor.get('description', 'N/A')[:200]}...")
        print(f"Aliases: {actor.get('aliases', [])}")
        print(f"Sofisticación: {actor.get('sophistication', 'N/A')}")
        print(f"Motivación: {actor.get('primary_motivation', 'N/A')}")
    
    return actors


def buscar_vulnerabilidades(cve_id):
    """Buscar vulnerabilidades por CVE"""
    print(f"\n🔓 Buscando vulnerabilidad: {cve_id}")
    print("=" * 60)
    
    vulns = opencti_api_client.vulnerability.list(
        filters={
            "mode": "and",
            "filters": [{"key": "name", "values": [cve_id], "operator": "eq"}],
            "filterGroups": []
        }
    )
    
    for vuln in vulns:
        print(f"\nCVE: {vuln.get('name')}")
        print(f"ID: {vuln.get('id')}")
        print(f"Descripción: {vuln.get('description', 'N/A')}")
        print(f"Severidad: {vuln.get('x_opencti_base_severity', 'N/A')}")
        print(f"CVSS Score: {vuln.get('x_opencti_cvss_base_score', 'N/A')}")
    
    return vulns


def listar_indicadores(limit=10):
    """Listar últimos indicadores de compromiso"""
    print(f"\n🎯 Últimos {limit} indicadores de compromiso")
    print("=" * 60)
    
    indicators = opencti_api_client.indicator.list(first=limit)
    
    for indicator in indicators:
        print(f"\nTipo: {indicator.get('pattern_type')}")
        print(f"Pattern: {indicator.get('pattern')}")
        print(f"Nombre: {indicator.get('name', 'N/A')}")
        print(f"Valid from: {indicator.get('valid_from')}")
        print(f"Valid until: {indicator.get('valid_until', 'N/A')}")
        print(f"Confianza: {indicator.get('confidence', 'N/A')}")
        print("-" * 40)
    
    return indicators


def buscar_observables(valor):
    """Buscar observables (IPs, dominios, hashes, etc.)"""
    print(f"\n🔍 Buscando observable: {valor}")
    print("=" * 60)
    
    observables = opencti_api_client.stix_cyber_observable.list(
        filters={
            "mode": "and",
            "filters": [{"key": "value", "values": [valor], "operator": "eq"}],
            "filterGroups": []
        }
    )
    
    for obs in observables:
        print(f"\nTipo: {obs.get('entity_type')}")
        print(f"Valor: {obs.get('observable_value')}")
        print(f"ID: {obs.get('id')}")
        print(f"Creado: {obs.get('created_at')}")
        print(f"Labels: {obs.get('objectLabel', [])}")
    
    return observables


def listar_reportes(limit=5):
    """Listar reportes de inteligencia"""
    print(f"\n📄 Últimos {limit} reportes de inteligencia")
    print("=" * 60)
    
    reports = opencti_api_client.report.list(first=limit)
    
    for report in reports:
        print(f"\nTítulo: {report.get('name')}")
        print(f"Publicado: {report.get('published')}")
        print(f"Descripción: {report.get('description', 'N/A')[:150]}...")
        print(f"Confianza: {report.get('confidence', 'N/A')}")
        print("-" * 40)
    
    return reports


def busqueda_global(texto):
    """Búsqueda global en OpenCTI"""
    print(f"\n🌐 Búsqueda global: {texto}")
    print("=" * 60)
    
    query = """
        query SearchGlobal($search: String!) {
            stixDomainObjects(search: $search, first: 10) {
                edges {
                    node {
                        id
                        entity_type
                        ... on ThreatActor {
                            name
                            description
                        }
                        ... on Malware {
                            name
                            description
                        }
                        ... on Vulnerability {
                            name
                            description
                        }
                    }
                }
            }
        }
    """
    
    try:
        # pycti query method usually returns the data directly
        result = opencti_api_client.query(query, {"search": texto})
        print(json.dumps(result, indent=2))
        return result
    except Exception as e:
        print(f"Error en búsqueda: {e}")
        return None


# ============================================
# EJEMPLOS DE USO
# ============================================

if __name__ == "__main__":
    print("\n" + "="*60)
    print("🔐 CONSULTAS A OPENCTI (Usando pycti)")
    print("="*60)
    
    # Descomenta las líneas para probar:
    
    # buscar_malware("Emotet")
    # buscar_actores_amenaza("APT29")
    # buscar_vulnerabilidades("CVE-2023-1234")
    listar_indicadores(5)
    # buscar_observables("192.168.1.1")
    listar_reportes(3)
    # busqueda_global("ransomware")
    
    print("\n✅ Script cargado. Edita el bloque 'if __name__' para ejecutar pruebas.")