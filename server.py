from fastmcp import FastMCP
from opencti_client import OpenCTIClient
from dotenv import load_dotenv
import os
from typing import Optional
import sys

# Cargar variables de entorno
load_dotenv()

# Inicializar el servidor FastMCP
mcp = FastMCP(
    "OpenCTI MCP"
)

# Inicializar el cliente (Lazy loading o global, aquí global para simplicidad)
try:
    client = OpenCTIClient()
except Exception as e:
    sys.stderr.write(f"Advertencia: No se pudo inicializar el cliente OpenCTI: {e}\n")
    client = None

@mcp.tool()
def search_threats(keyword: str, limit: int = 5) -> str:
    """
    Busca amenazas, observables o entidades en OpenCTI basándose en una palabra clave.
    Útil para encontrar malware, actores de amenazas o CVEs específicos.
    
    Args:
        keyword: Término de búsqueda (ej. "Emotet", "CVE-2023-1234", "192.168.1.1").
        limit: Número máximo de resultados a devolver (por defecto 5).
    """
    if not client:
        return "Error: El cliente OpenCTI no está configurado correctamente."
    
    try:
        results = client.search_knowledge(keyword, limit)
        if not results:
            return f"No se encontraron resultados para '{keyword}'."
        return str(results)
    except Exception as e:
        return f"Error al buscar en OpenCTI: {str(e)}"

@mcp.tool()
def list_latest_indicators(limit: int = 10, pattern_type: Optional[str] = None) -> str:
    """
    Lista los últimos indicadores de compromiso (IOCs) registrados en la plataforma.
    
    Args:
        limit: Cantidad de indicadores a recuperar.
        pattern_type: (Opcional) Filtrar por tipo (ej. "stix", "pcre", "sigma", "snort").
    """
    if not client:
        return "Error: Configuración incompleta."
    
    try:
        indicators = client.get_indicators(limit, filter_type=pattern_type)
        return str(indicators)
    except Exception as e:
        return f"Error al obtener indicadores: {str(e)}"

@mcp.tool()
def get_intelligence_reports(limit: int = 5) -> str:
    """
    Obtiene los reportes de inteligencia más recientes publicados en OpenCTI.
    Útil para obtener contexto estratégico o resúmenes de campañas.
    """
    if not client:
        return "Error: Configuración incompleta."

    try:
        reports = client.get_reports(limit)
        return str(reports)
    except Exception as e:
        return f"Error al obtener reportes: {str(e)}"

@mcp.tool()
def get_entity_by_id(entity_id: str) -> str:
    """
    Obtiene todos los detalles disponibles de una entidad específica usando su ID de OpenCTI.
    
    Args:
        entity_id: El ID único de la entidad (ej. "malware--uuid...").
    """
    if not client:
        return "Error: Configuración incompleta."

    try:
        details = client.get_entity_details(entity_id)
        if not details:
            return "No se encontró ninguna entidad con ese ID."
        return str(details)
    except Exception as e:
        return f"Error al obtener detalles de la entidad: {str(e)}"

if __name__ == "__main__":
    # FastMCP maneja automáticamente la ejecución (run) o servicio (serve)
    mcp.run()
