import os
from pycti import OpenCTIApiClient
from typing import Optional, Dict, Any, List
import logging

# Configurar logging de pycti a ERROR para que no ensucie la salida estándar (stdio)
# que usa el protocolo MCP.
logging.getLogger('pycti').setLevel(logging.ERROR)

class OpenCTIClient:
    def __init__(self):
        self.url = os.getenv("OPENCTI_URL")
        self.token = os.getenv("OPENCTI_TOKEN")
        
        if not self.url or not self.token:
            raise ValueError("Faltan las variables de entorno OPENCTI_URL o OPENCTI_TOKEN")

        # Inicializar el cliente oficial
        # log_level='error' es importante para evitar ruido en la consola
        self.api = OpenCTIApiClient(self.url, self.token, log_level='error')

    def search_knowledge(self, keyword: str, limit: int = 10) -> List[Dict]:
        """Busca en todo el conocimiento de OpenCTI (Stix Domain Objects)."""
        # En OpenCTI 6+, usamos la búsqueda sobre objetos de dominio
        return self.api.stix_domain_object.list(
            search=keyword,
            first=limit
        )

    def get_indicators(self, limit: int = 10, filter_type: Optional[str] = None) -> List[Dict]:
        """Obtiene los últimos indicadores de compromiso."""
        filters = None
        if filter_type:
            # Formato de filtros JSON compatible con OpenCTI 6.x
            filters = {
                "mode": "and",
                "filters": [{
                    "key": "pattern_type",
                    "values": [filter_type],
                    "operator": "eq",
                    "mode": "or"
                }],
                "filterGroups": []
            }

        return self.api.indicator.list(
            first=limit,
            filters=filters,
            orderBy="created_at",
            orderMode="desc"
        )

    def get_reports(self, limit: int = 5) -> List[Dict]:
        """Obtiene los reportes de inteligencia más recientes."""
        return self.api.report.list(
            first=limit,
            orderBy="published",
            orderMode="desc"
        )

    def get_entity_details(self, entity_id: str) -> Dict:
        """Obtiene detalles profundos de una entidad específica."""
        # stix_domain_object.read busca automáticamente por ID
        return self.api.stix_domain_object.read(id=entity_id)
