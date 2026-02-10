# OpenCTI MCP Server

Este repositorio contiene un servidor de **Model Context Protocol (MCP)** diseñado para interactuar con una instancia de [OpenCTI](https://www.opencti.io/). Permite que asistentes de IA (como Claude Desktop) consulten amenazas, indicadores de compromiso y reportes de inteligencia directamente desde tu plataforma de Ciberinteligencia.

## 🚀 Características

- **Búsqueda Global**: Localiza malware, actores de amenazas o CVEs por palabra clave.
- **Indicadores de Compromiso (IOCs)**: Recupera los últimos indicadores registrados con soporte para filtros por tipo (STIX, PCRE, Sigma, etc.).
- **Reportes de Inteligencia**: Acceso a los informes más recientes para obtener contexto estratégico.
- **Detalles de Entidad**: Consulta profunda de información técnica usando IDs específicos de OpenCTI.

## 📋 Requisitos Previos

- Python 3.10 o superior.
- Una instancia activa de OpenCTI.
- Un Token de API válido de OpenCTI.

## 🛠️ Instalación

1. **Clonar el repositorio:**
   ```bash
   git clone 
   cd mcp-opencti
