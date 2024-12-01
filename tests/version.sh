#!/bin/bash

echo "=== Consultando versión del programa ==="

response=$(curl -s -w "\nHTTP_STATUS_CODE:%{http_code}\n" -X GET "https://myserver.local:5000/version" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" -k)

http_status=$(echo "$response" | grep "HTTP_STATUS_CODE" | awk -F: '{print $2}' | tr -d '[:space:]')
response_body=$(echo "$response" | sed -e 's/HTTP_STATUS_CODE:.*//g')

if [[ -n "$http_status" && "$http_status" -eq 200 ]]; then
  echo "Versión obtenida exitosamente: $response_body"
else
  echo "Error al obtener la versión. Código HTTP: $http_status"
  echo "Respuesta del servidor: $response_body"
fi
