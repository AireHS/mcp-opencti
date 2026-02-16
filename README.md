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
   git clone https://github.com/tu-usuario/mcp-opencti.git
   cd mcp-opencti
   ```

2. **Instalar dependencias:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Configurar entorno:**
   - Copia el archivo de ejemplo:
     ```bash
     cp .env.example .env
     ```
   - Edita `.env` y agrega tu URL de OpenCTI y tu Token.

## 🧪 Verificación

Antes de configurar los clientes, puedes verificar que la conexión con OpenCTI funciona correctamente usando el script de pruebas incluido:

```bash
python opencti_queries.py
```

Si ves una lista de indicadores y reportes en la consola, tu entorno está configurado correctamente.

## 🖥️ Uso con Claude Desktop

Edita tu archivo de configuración de Claude (`%APPDATA%\Claude\claude_desktop_config.json`) y agrega:

   ```json
   {
     "mcpServers": {
       "opencti": {
         "command": "python",
         "args": [
           "C:\\ruta\\absoluta\\a\\tu\\proyecto\\start_claude.py"
         ]
       }
     }
   }
   ```

## ⚡ Uso con n8n (Web / SSE)

Para integrar con n8n, necesitas levantar el servidor en modo HTTP:

1. **Iniciar el servidor:**
   ```bash
   python start_n8n.py
   ```

2. **En n8n:**
   - Usa un nodo **MCP** (si está disponible) o configura una conexión SSE.
   - Conecta a la URL: `http://localhost:8000/sse`