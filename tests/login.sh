#!/bin/bash

echo "=== Iniciando sesión ==="

read -p "Nombre de usuario: " username
read -s -p "Contraseña: " password
echo

response=$(curl -s -X POST "https://myserver.local:5000/login" \
  -H "Content-Type: application/json" \
  -d "{\"Usuario\": \"$username\", \"Contraseña\": \"$password\"}" -k)

# Intentar extraer el token de 'access_token' o 'token_acceso'
token=$(echo "$response" | jq -r '.access_token // .token_acceso // empty')

if [[ -n "$token" ]]; then
  echo "Inicio de sesión exitoso. {token: $token}"
  
  # Crear la carpeta del usuario si no existe
  user_dir="users/$username"
  mkdir -p "$user_dir"
  
  # Solicitar el ID del usuario
  read -p "Ingrese el ID del usuario: " user_id
  
  # Guardar el username, password, token y ID en un archivo JSON en la carpeta del usuario
  user_file="$user_dir/$user_id.json"
  echo "{\"username\":\"$username\", \"password\":\"$password\", \"token\":\"$token\", \"ID\":\"$user_id\"}" > "$user_file"
  echo "Datos guardados en $user_file."
  
  # Guardar el nombre de usuario en un archivo
  echo "$username" > "current_user.txt"
  
  echo "Nota: Este token expira en 5 minutos. Deberá volver a iniciar sesión para obtener un nuevo token."
else
  echo "Error al iniciar sesión. Respuesta: $response"
  exit 1
fi