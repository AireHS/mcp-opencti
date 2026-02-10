import sys
from fastmcp.cli import app

if __name__ == "__main__":
    # Simula los argumentos de línea de comandos
    sys.argv = ["fastmcp", "dev", "server.py"]
    sys.exit(app())
