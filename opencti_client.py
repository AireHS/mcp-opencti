import os
import requests
import json
from typing import Optional, Dict, Any, List

class OpenCTIClient:
    def __init__(self):
        self.url = os.getenv("OPENCTI_URL")
        self.token = os.getenv("OPENCTI_TOKEN")
        
        if not self.url or not self.token:
            raise ValueError("Faltan las variables de entorno OPENCTI_URL o OPENCTI_TOKEN")

        # Asegurar que la URL termine en /graphql
        if not self.url.endswith("/graphql"):
            self.url = f"{self.url.rstrip('/')}/graphql"

        self.headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json"
        }

    def _execute_query(self, query: str, variables: Dict[str, Any] = None) -> Dict[str, Any]:
        """Ejecuta una query GraphQL con manejo de errores robusto."""
        try:
            response = requests.post(
                self.url,
                headers=self.headers,
                json={"query": query, "variables": variables or {}},
                timeout=30
            )
            response.raise_for_status()
            
            data = response.json()
            
            if "errors" in data:
                error_msgs = [e["message"] for e in data["errors"]]
                raise Exception(f"Errores de GraphQL OpenCTI: {'; '.join(error_msgs)}")
                
            return data.get("data", {})

        except requests.exceptions.RequestException as e:
            raise Exception(f"Error de conexión HTTP con OpenCTI: {str(e)}")
        except json.JSONDecodeError:
            raise Exception("Respuesta inválida de OpenCTI (No es JSON)")

    def search_knowledge(self, keyword: str, limit: int = 10) -> List[Dict]:
        """Busca en todo el conocimiento de OpenCTI."""
        query = """
        query GlobalSearch($keyword: String!, $first: Int) {
          globalSearch(keyword: $keyword, first: $first) {
            edges {
              node {
                id
                entity_type
                ... on StixDomainObject {
                  created_at
                  name
                  description
                }
                ... on StixCyberObservable {
                  observable_value
                }
              }
            }
          }
        }
        """
        data = self._execute_query(query, {"keyword": keyword, "first": limit})
        return [edge["node"] for edge in data.get("globalSearch", {}).get("edges", [])]

    def get_indicators(self, limit: int = 10, filter_type: Optional[str] = None) -> List[Dict]:
        """Obtiene los últimos indicadores de compromiso."""
        # Nota: La query puede variar según la versión de OpenCTI, esta es estándar v5/v6
        query = """
        query GetIndicators($first: Int, $filters: [IndicatorFiltering!]) {
          indicators(first: $first, filters: $filters) {
            edges {
              node {
                id
                name
                pattern
                pattern_type
                valid_from
                indicator_types
                created_at
              }
            }
          }
        }
        """
        variables = {"first": limit, "filters": []}
        if filter_type:
            variables["filters"].append({"key": "pattern_type", "values": [filter_type]})

        data = self._execute_query(query, variables)
        return [edge["node"] for edge in data.get("indicators", {}).get("edges", [])]

    def get_reports(self, limit: int = 5) -> List[Dict]:
        """Obtiene los reportes de inteligencia más recientes."""
        query = """
        query GetReports($first: Int) {
          reports(first: $first, orderBy: published, orderMode: desc) {
            edges {
              node {
                id
                name
                description
                published
                report_types
                objectLabel {
                  edges {
                    node {
                      value
                    }
                  }
                }
              }
            }
          }
        }
        """
        data = self._execute_query(query, {"first": limit})
        return [edge["node"] for edge in data.get("reports", {}).get("edges", [])]

    def get_entity_details(self, entity_id: str) -> Dict:
        """Obtiene detalles profundos de una entidad específica."""
        query = """
        query GetEntity($id: String!) {
          stixDomainObject(id: $id) {
            id
            name
            description
            aliases
            created_at
            updated_at
            ... on Report {
                published
            }
            ... on Malware {
                is_family
            }
          }
        }
        """
        data = self._execute_query(query, {"id": entity_id})
        return data.get("stixDomainObject", {})
