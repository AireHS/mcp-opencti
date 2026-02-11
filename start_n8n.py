from server import mcp

if __name__ == "__main__":
    # Usamos el puerto 8081 para evitar conflictos con el 8000 (Error 10013)
    mcp.run(transport="sse", port=8081)
