#!/bin/bash

echo "=== Operación sobre documento ==="

read -p "Nombre de usuario: " username
read -p "Nombre del documento: " doc_name

# Leer el contenido del archivo JSON correspondiente al user_id
user_dir="users/$username"
id_file="$user_dir/$doc_name.json"

if [[ ! -f "$id_file" ]]; then 
    echo "Error: No se encontró el archivo de autenticación para el usuario $username."
    exit 1
fi

user_id=$(jq -r '.ID' "$id_file")
token=$(jq -r '.token' "$id_file")

if [[ -z "$user_id" ]]; then
    echo "Error: ID de usuario no válido o ausente."
    exit 1
fi

echo "Seleccione la operación a realizar:"
echo "1. GET: Obtener el contenido del documento"
echo "2. POST: Crear un nuevo documento"
echo "3. PUT: Actualizar un documento existente"
echo "4. DELETE: Borrar un documento"
read -p "Ingrese el número de la operación: " operation

case $operation in
    1)
        # Leer el contenido del archivo .json correspondiente al documento
        doc_file="users/$username/$doc_name.json"
        
        if [[ ! -f "$doc_file" ]]; then
            echo "Error: No se encontró el archivo $doc_file."
            exit 1
        fi
        
        doc_content=$(cat "$doc_file")
        
        response=$(curl -s -X GET "https://myserver.local:5000/docs/$doc_name" \
            -H "Authorization: Bearer $token" \
            -H "Content-Type: application/json" \
            -d "{\"ID\": \"$user_id\"}" -k)
        ;;
    2)
        read -p "Ingrese el contenido del nuevo documento: " doc_content
        response=$(curl -s -X POST "https://myserver.local:5000/docs" \
            -H "Authorization: Bearer $token" \
            -H "Content-Type: application/json" \
            -d "{\"ID\": \"$user_id\", \"doc_name\": \"$doc_name\", \"content\": \"$doc_content\"}" -k)
        ;;
    3)
        read -p "Ingrese el nuevo contenido del documento: " doc_content
        response=$(curl -s -X PUT "https://myserver.local:5000/docs/$doc_name" \
            -H "Authorization: Bearer $token" \
            -H "Content-Type: application/json" \
            -d "{\"ID\": \"$user_id\", \"content\": \"$doc_content\"}" -k)
        ;;
    4)
        response=$(curl -s -X DELETE "https://myserver.local:5000/docs/$doc_name" \
            -H "Authorization: Bearer $token" \
            -H "Content-Type: application/json" \
            -d "{\"ID\": \"$user_id\"}" -k)
        ;;
    *)
        echo "Operación no válida."
        exit 1
        ;;
esac

echo "Respuesta del servidor: $response"