#!/bin/bash

echo "=== Registrando nuevo usuario ==="

read -p "Nombre de usuario: " username
read -s -p "Contraseña: " password
echo
read -s -p "Confirme la contraseña: " password_confirm
echo
read -p "ID de usuario: " user_id

if [[ "$password" != "$password_confirm" ]]; then
  echo "Error: Las contraseñas no coinciden."
  exit 1
fi

response=$(curl -s -X POST "https://myserver.local:5000/signup" \
  -H "Content-Type: application/json" \
  -d "{\"Usuario\": \"$username\", \"Contraseña\": \"$password\", \"ID\": \"$user_id\"}" -k)

token=$(echo "$response" | jq -r '.access_token // empty')

if [[ -n "$token" ]]; then
  echo "Usuario registrado con éxito. {token: $token}"
  
  # Crear la carpeta del usuario si no existe
  user_dir="users/$username"
  mkdir -p "$user_dir"
  
  # Guardar el username, password, token y ID en un archivo JSON en la carpeta del usuario
  echo "{\"username\":\"$username\", \"password\":\"$password\", \"token\":\"$token\", \"ID\":\"$user_id\"}" > "$user_dir/$user_id.json"
  echo "Datos almacenados en $user_dir/$user_id.json."
  
  echo "Nota: Este token expira en 5 minutos. Deberá volver a iniciar sesión para obtener un nuevo token."
else
  echo "Error al registrar usuario. Respuesta: $response"
  exit 1
fi