#!/bin/bash

# GET: Obtener todos los documentos de un usuario
# Argumento: username

if [ $# -ne 1 ]; then
    echo "Uso: $0 <username>"
    exit 1
fi

username=$1

# Leer el token desde el archivo JSON del usuario
user_dir="users/$username"
id_file="$user_dir/$username.json"

if [[ ! -f "$id_file" ]]; then 
    echo "Error: No se encontró el archivo de autenticación para el usuario $username."
    exit 1
fi

token=$(jq -r '.token' "$id_file")

# Verifica que el token no esté vacío
if [ -z "$token" ]; then
    echo "Se requiere un token de autenticación. Usa /login o /signup para obtenerlo."
    exit 1
fi

response=$(curl -s -o /dev/null -w "%{http_code}" -X GET "https://myserver.local:5000/users/$username/_all_docs" \
    -k \
    -H "Authorization: token $token")

if [ "$response" -eq 200 ]; then
    echo "Operación realizada con éxito."
else
    echo "Error en la operación. Código de respuesta: $response"
fi