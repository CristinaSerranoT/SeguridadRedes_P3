# Directorios y variables
DIRUSER := users/
DIRTEST := tests/
SHADOW := .shadow

# Dependencias de Go
dependencias:
	go get github.com/dgrijalva/jwt-go
	go get github.com/gin-gonic/gin
	go get github.com/google/uuid
	go get github.com/joho/godotenv

# Comando para ejecutar la aplicación
run:
	go build main.go
	go run main.go

# Pruebas
test:
	./$(DIRTEST)/version.sh $(username) $(password)
	./$(DIRTEST)/signup.sh $(username) $(password)
	./$(DIRTEST)/login.sh $(username) $(password)
	./$(DIRTEST)/doc_id.sh $(username) $(file)

# Limpiar archivos generados
clean: cleanUsers cleanShadow

# Limpiar directorios de usuarios
cleanUsers:
	rm -rf $(DIRUSER)

# Limpiar archivo shadow
cleanShadow:
	rm $(SHADOW)