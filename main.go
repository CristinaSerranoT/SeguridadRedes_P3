package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"time"
	"unicode"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
)

const (
	VERSION         = "v1.0.0"
	USERS_PATH      = "users/"
	SHADOW_FILE     = ".shadow"
	TIME_EXPIRATION = 5
)

var TOKENS_DICT = make(map[string]string)

type Signup struct{}
type Login struct{}
type Version struct{}
type User struct{}
type Docs struct{}


// ------------------------------------------------------------ENV------------------------------------------------------------------

// Cargar variables de entorno desde el archivo .env
func loadVariablesEnviroment() {
	if err := godotenv.Load(); err != nil {
		fmt.Println("Error al cargar el archivo .env")
	}
}

// Obtener la clave secreta desde las variables de entorno
func getSecretKey() string {
	loadVariablesEnviroment()
	key := os.Getenv("SECRET_KEY")
	if key == "" {
		fmt.Println("Error: SECRET_KEY no está definida en el archivo .env")
		os.Exit(1)
	}
	return key
}

// Función para validar el formato del userID
func isValidUserID(userID string) bool {
	if len(userID) == 0 {
		return false
	}
	for _, char := range userID {
		if !unicode.IsLetter(char) && !unicode.IsDigit(char) && char != '-' {
			return false
		}
	}
	return true
}

// ------------------------------------------------------------MIDDLEWARE------------------------------------------------------------

// Middleware que comprueba la cabecera Authorization para asegurarse de que el usuario está autorizado a realizar la petición.
func AuthorizationMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		userID := c.Param("user_id")
		fmt.Println("Valor de userID recibido:", userID)

		// Permitir acceso a las rutas de login y signup sin token
		if c.FullPath() == "/login" || c.FullPath() == "/signup" {
			c.Next()
			return
		}

		// Verificar si el userID está presente y tiene un formato válido
		userID = strings.TrimSpace(userID)
		if !isValidUserID(userID) {
			fmt.Println("ID de usuario no válido o ausente:", userID)
			c.JSON(404, gin.H{"Mensaje": "ID de usuario no válido o ausente"})
			c.Abort()
			return
		}

		// Comprobar cabecera Authorization y verificar el token
		if checkAuthorizationHeader(c, userID) {
			c.Next()
		} else {
			fmt.Println("Autorización fallida para el usuario:", userID)
			c.JSON(401, gin.H{"Mensaje": "Acceso no autorizado"})
			c.Abort()
		}
	}
}

// Comprueba la cabecera Authorization y verifica el token del usuario.
func checkAuthorizationHeader(c *gin.Context, userID string) bool {
	signup := Signup{}
	// Obtiene la cabecera Authorization de la petición
	authHeader := c.GetHeader("Authorization")
	fmt.Println("Cabecera de Autorización:", authHeader)
	header := strings.Split(authHeader, " ")
	if len(header) != 2 || strings.ToLower(header[0]) != "token" {
		c.JSON(400, gin.H{"Mensaje": "Formato de cabecera no válido"})
		return false
	}

	// Extrae el token de la cabecera
	token := header[1]

	// Verifica la autenticidad del token
	if signup.VerifyToken(userID, token, c) {
		return true
	} else {
		c.JSON(401, gin.H{"Mensaje": "Token no válido o ausente"})
		return false
	}
}

// ------------------------------------------------------------VERSION------------------------------------------------------------

// VERSION: Contiene la versión actual de la API
func (v *Version) Get(c *gin.Context) {
    fmt.Println("Version: ", VERSION)
    c.JSON(200, gin.H{"Version:": VERSION})
}

// ------------------------------------------------------------SIGNUP------------------------------------------------------------

// Create a directory for the user
func (s *Signup) CreateUserSpace(username string, c *gin.Context) {
	if err := os.MkdirAll("users/"+username, 0755); err != nil {
		c.JSON(500, gin.H{"Error": "Error al crear el espacio del usuario"})
		return
	}
	fmt.Println("¡Espacio de usuario creado correctamente!")
}

// Registrar un usuario en el archivo shadow
func (s *Signup) RegisterUser(username, password string, c *gin.Context) {
	shadowFile, err := os.OpenFile(SHADOW_FILE, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		c.JSON(500, gin.H{"Error": "Error al abrir el archivo shadow"})
		return
	}
	defer shadowFile.Close()

	// Generar un salt aleatorio
	salt := uuid.New().String()

	// Añadir un salto de línea si el archivo no está vacío
	if _, err := shadowFile.Stat(); err == nil {
		_, _ = shadowFile.WriteString("\n")
	}

	// Encriptar la contraseña usando el salt generado
	hashedPassword := s.EncryptPassword(salt, password)

	// Escribir la información en el archivo shadow
	if _, err := shadowFile.WriteString(fmt.Sprintf("%s:%s:%s\n", username, salt, hashedPassword)); err != nil {
		c.JSON(500, gin.H{"Error": "Error al escribir en el archivo shadow"})
		return
	}
	
	fmt.Println("¡Usuario registrado correctamente!")
}

// Método para comprobar si un usuario ya está registrado
func (s *Signup) CheckUsername(username string) bool {

	// Abre el archivo shadow
	shadowFile, err := os.Open(SHADOW_FILE)
	if err != nil {
	return false
	}
	defer shadowFile.Close()

	// Lee el archivo línea por línea
	scanner := bufio.NewScanner(shadowFile)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Split(line, ":")[0] == username {
			return true
		}
	}
	return false
}

// Encriptar la contraseña con SHA-256 y añadir un salt
func (s *Signup) EncryptPassword(salt, password string) string {

	// Crear un hash SHA-256
	hash := sha256.New()

	// Concatena el salt y la contraseña y hashea el resultado
	hash.Write([]byte(salt + password))

	// Devuelve el hash en formato hexadecimal
	return hex.EncodeToString(hash.Sum(nil))
}

// Generar un token de acceso para el usuario
func (s *Signup) GenerateAccessToken(username string, c *gin.Context) string {

	// Genera un token con un tiempo de expiración de 5 minutos
	exp := time.Now().Add(time.Minute * TIME_EXPIRATION).Unix()

	// Crea un JWT con el nombre de usuario y el tiempo de expiración
	claims := jwt.StandardClaims{
		Subject:   username,
		ExpiresAt: exp,
	}

	// Crea un token firmado con el algoritmo HS256 y la clave secreta
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := token.SignedString([]byte(getSecretKey()))
	if err != nil {
		c.JSON(500, gin.H{"Error": "Error al firmar el token"})
		return ""
	}
	return signedToken
}

// Método para registrar un usuario
func (s *Signup) SignUp(c *gin.Context) {
	var jsonInput map[string]string
	if err := c.BindJSON(&jsonInput); err != nil {
		c.JSON(400, gin.H{"Error": "Formato inválido."})
		return
	}

	// Comprueba si los campos 'Usuario' y 'Contraseña' están presentes
	username, uOk := jsonInput["Usuario"]
	password, pOk := jsonInput["Contraseña"]
	if !uOk || !pOk {
		c.JSON(400, gin.H{"Error": "Los argumentos deben ser 'Usuario' or 'Contraseña'"})
		return
	}

	// Comprueba si el usuario ya está registrado
	if s.CheckUsername(username) {
		c.JSON(409, gin.H{"Error": fmt.Sprintf("Error, el usuario %s ya existe. Por favor, pruebe de nuevo.", username)})
		return
	}

	// Registra al usuario y crea su espacio
	s.RegisterUser(username, password, c)
	s.CreateUserSpace(username, c)

	// Genera un token de acceso y lo almacena en el diccionario
	token := s.GenerateAccessToken(username, c)
	TOKENS_DICT[username] = token

	c.JSON(200, gin.H{"access_token": token})
}

// Método para verificar un token
func (s *Signup) VerifyToken(username, tokenString string, c *gin.Context) bool {
    token, err := jwt.ParseWithClaims(tokenString, &jwt.StandardClaims{}, func(token *jwt.Token) (interface{}, error) {
        // Proporciona la clave utilizada para firmar el token
        return []byte(getSecretKey()), nil
    })

    if err != nil {
		var message string
		if err == jwt.ErrSignatureInvalid {
			message = "Firma del token inválida"
		} else if ve, ok := err.(*jwt.ValidationError); ok && ve.Errors == jwt.ValidationErrorExpired {
			message = "El token ha expirado"
		} else {
			message = "Error al analizar el token"
		}
		c.JSON(401, gin.H{"Error": message})
		return false
	}
	

    // Comprueba si el token es válido y si los claims coinciden con el nombre de usuario proporcionado
    if claims, ok := token.Claims.(*jwt.StandardClaims); ok && token.Valid {
        if claims.Subject == username {
            return true
        } else {
            c.JSON(401, gin.H{"Error": "El token no coincide con el usuario"})
            return false
        }
    }

    c.JSON(401, gin.H{"Error": "Token inválido"})
    return false
}

// ------------------------------------------------------------LOGIN------------------------------------------------------------

// Comprueba las credenciales del usuario
func (l *Login) CheckCredentials(username, password string, c *gin.Context) bool {

	signup := Signup{}

	// Abre el archivo shadow
	shadowFile, err := os.Open(SHADOW_FILE)
	if err != nil {
		c.JSON(500, gin.H{"error": "Error opening shadow file"})
		return false
	}
	defer shadowFile.Close()

	// Lee el archivo línea por línea
	scanner := bufio.NewScanner(shadowFile)
	for scanner.Scan() {
		line := scanner.Text()
		credentials := strings.Split(line, ":")
		if credentials[0] == username {
			// Encripta la contraseña proporcionada con la salt almacenada en el archivo shadow
			hashedPassword := signup.EncryptPassword(credentials[1], password)
			if err != nil {
				c.JSON(500, gin.H{"error": "Error encrypting password"})
				return false
			}
			// Comprueba si la contraseña encriptada coincide con la almacenada en el archivo shadow
			if strings.TrimSpace(credentials[2]) == hashedPassword {
				return true
			}
		}
	}
	return false
}

// Inicia sesión en el sistema
func (l *Login) Login(c *gin.Context) {
	var jsonInput map[string]string
	if err := c.BindJSON(&jsonInput); err != nil {
		c.JSON(400, gin.H{"Error": "Formato inválido."})
		return
	}

	username, uOk := jsonInput["Usuario"]
	password, pOk := jsonInput["Contraseña"]
	if !uOk || !pOk {
		c.JSON(400, gin.H{"Error": "Los argumentos deben ser 'Usuario' o 'Contraseña'"})
		return
	}

	if l.CheckCredentials(username, password, c) {
		signup := Signup{}
		token, exists := TOKENS_DICT[username]
		if !exists || !signup.VerifyToken(username, token, c) {
			token = signup.GenerateAccessToken(username, c)
			TOKENS_DICT[username] = token
		}
		c.JSON(200, gin.H{"token_acceso": token})
	} else {
		c.JSON(401, gin.H{"Error": "Credenciales inválidas"})
	}
}

// ------------------------------------------------------------USER------------------------------------------------------------

// GET: Obtener los datos de un usuario basado en el id del usuario y el id del documento
func (u *User) Get(c *gin.Context) {
	userID := c.Param("user_id")
	docID := c.Param("doc_name")

	// Comprueba la cabecera de autorización y verifica el token
	if !checkAuthorizationHeader(c, userID) {
		c.JSON(401, gin.H{"Mensaje": "El token no es correcto"})
		return
	}

	// Construye la ruta del archivo JSON
	jsonFileName := USERS_PATH + userID + "/" + docID + ".json"
	if _, err := os.Stat(jsonFileName); os.IsNotExist(err) {
		c.JSON(404, gin.H{"Mensaje": "El archivo no existe"})
		return
	}

	// Abre el archivo JSON
	jsonFile, err := os.Open(jsonFileName)
	if err != nil {
		c.JSON(500, gin.H{"Error": "Error al abrir el archivo JSON"})
		return
	}
	defer jsonFile.Close()

	// Decodifica el contenido JSON en una interfaz genérica
	var data interface{}
	decoder := json.NewDecoder(jsonFile)
	if err := decoder.Decode(&data); err != nil {
		c.JSON(500, gin.H{"Error": "Error al decodificar el archivo JSON"})
		return
	}

	c.JSON(200, data)
}


// POST: Crear un nuevo documento para un usuario
func (u *User) Post(c *gin.Context) {

	userID := c.Param("user_id")
	docID := c.Param("doc_name")

	// Comprueba la cabecera de autorización y verifica el token
	if checkAuthorizationHeader(c, userID) {
		if _, err := os.Stat(USERS_PATH + userID + "/" + docID + ".json"); !os.IsNotExist(err) {
			c.JSON(405, gin.H{"Mensaje": "El archivo ya existe. Utilice PUT para actualizar el archivo"})
			return
		}

		// Extrae el contenido del documento de la entrada JSON
		var jsonInput map[string]interface{}
		if err := c.BindJSON(&jsonInput); err != nil {
			c.JSON(400, gin.H{"Mensaje": "Formato incorrecto"})
			return
		}

		// Construye la ruta del archivo JSON
		docContent, exists := jsonInput["contenido_documento"]
		if !exists {
			c.JSON(400, gin.H{"Mensaje": "El campo 'contenido_documento' es obligatorio"})
			return
		}

		// Construye la ruta del archivo JSON
		jsonFileName := USERS_PATH + userID + "/" + docID + ".json"

		// Codifica el contenido JSON en una cadena
		jsonString, err := json.Marshal(docContent)
		if err != nil {
			c.JSON(500, gin.H{"Mensaje": "Error interno del servidor"})
			return
		}

		// Escribe el contenido JSON en el archivo
		err = ioutil.WriteFile(jsonFileName, jsonString, 0644)
		if err != nil {
			c.JSON(500, gin.H{"Mensaje": "Error interno del servidor"})
			return
		}

		// Obtiene información sobre el archivo creado
		fileInfo, err := os.Stat(jsonFileName)
		if err != nil {
			c.JSON(500, gin.H{"Mensaje": "Error interno del servidor"})
			return
		}
		c.JSON(200, gin.H{"Tamaño": fileInfo.Size()})

	} else {
		c.JSON(401, gin.H{"Mensaje": "El token no es correcto"})
	}
}

// PUT: Actualizar un documento para un usuario
func (u *User) Put(c *gin.Context) {

	userID := c.Param("user_id")
	docID := c.Param("doc_name")

	if checkAuthorizationHeader(c, userID) {
		jsonFilePath := fmt.Sprintf("%s%s/%s.json", USERS_PATH, userID, docID)

		if _, err := os.Stat(jsonFilePath); os.IsNotExist(err) {
			c.JSON(404, gin.H{"Mensaje": "El archivo no existe"})	
			return
		}

		// Lee el contenido actual del archivo
		currentContent, err := ioutil.ReadFile(jsonFilePath)
		if err != nil {
			c.JSON(500, gin.H{"Mensaje": "Error interno del servidor"})
			return
		}

		// Decodifica el contenido actual en un mapa
		var currentJSON map[string]interface{}
		err = json.Unmarshal(currentContent, &currentJSON)
		if err != nil {
			c.JSON(500, gin.H{"Mensaje": "Error interno del servidor"})
			return
		}

		// Extrae el nuevo contenido del documento de la entrada JSON
		var newContent map[string]interface{}
		if err := c.BindJSON(&newContent); err != nil {
			c.JSON(400, gin.H{"Mensaje": "Formato incorrecto"})
			return
		}

		// Actualiza el contenido actual con el nuevo contenido
		for key, value := range newContent {
			currentJSON[key] = value
		}

		// Codifica el nuevo contenido en una cadena
		newContentString, err := json.Marshal(currentJSON)
		if err != nil {
			c.JSON(500, gin.H{"Mensaje": "Error interno del servidor"})
			return
		}

		// Escribe el nuevo contenido en el archivo
		err = ioutil.WriteFile(jsonFilePath, newContentString, 0644)
		if err != nil {
			c.JSON(500, gin.H{"Mensaje": "Error interno del servidor"})
			return
		}

		// Obtiene información sobre el archivo actualizado
		fileInfo, err := os.Stat(jsonFilePath)
		if err != nil {
			c.JSON(500, gin.H{"Mensaje": "Error interno del servidor"})
			return
		}
		c.JSON(200, gin.H{"Tamaño": fileInfo.Size()})

	} else {
		c.JSON(401, gin.H{"Mensaje": "El token no es correcto"})
	}
}

// DELETE: Eliminar un documento para un usuario
func (u *User) Delete(c *gin.Context) {

	userID := c.Param("user_id")
	docID := c.Param("doc_name")

	// Comprueba la cabecera de autorización y verifica el token
	if checkAuthorizationHeader(c, userID) {

		// Construye la ruta del archivo JSON
		jsonFilePath := fmt.Sprintf("%s%s/%s.json", USERS_PATH, userID, docID)

		// Comprueba si el archivo existe
		if _, err := os.Stat(jsonFilePath); os.IsNotExist(err) {
			c.JSON(404, gin.H{"Mensaje": "El archivo no existe"})
			return
		}

		// Elimina el archivo JSON
		err := os.Remove(jsonFilePath)
		if err != nil {
			c.JSON(400, gin.H{"Mensaje": "Error al eliminar el archivo"})
			return
		}
		c.JSON(200, gin.H{})

	} else {
		c.JSON(401, gin.H{"Mensaje": "El token no es correcto"})
	}
}


// ------------------------------------------------------------DOCS------------------------------------------------------------

// GET: Obtener los datos de un usuario basado en el id del usuario y el id del documento
func (d *Docs) Get(c *gin.Context) {

	userID := c.Param("user_id")

	// Comprueba la cabecera de autorización y verifica el token
	if checkAuthorizationHeader(c, userID) {
		allDocs := make(map[string]interface{})

		//Lee todos los archivos en el espacio del usuario
		path, err := os.ReadDir(USERS_PATH + userID)
		if err != nil {
			c.JSON(400, gin.H{"Mensaje": "Error al leer el directorio del usuario"})
			return
		}

		// Itera sobre los archivos y lee su contenido
		for _, entry := range path {
			fileName := entry.Name()
			filePath := fmt.Sprintf("%s%s/%s", USERS_PATH, userID, fileName)

			// Lee el contenido del archivo
			fileContent, err := os.ReadFile(filePath)
			if err != nil {
				c.JSON(400, gin.H{"Mensaje": "Error al leer el archivo"})
				return
			}

			// Decodifica el contenido JSON en un mapa
			var docContent map[string]interface{}
			if err := json.Unmarshal(fileContent, &docContent); err != nil {
				c.JSON(400, gin.H{"Mensaje": "Error al decodificar el archivo JSON"})
				return
			}

			// Almacena el contenido del archivo en un mapa
			allDocs[fileName[:len(fileName)-5]] = docContent
		}
		c.JSON(200, allDocs)

	} else {
		c.JSON(401, gin.H{"Mensaje": "El token no es correcto"})
	}
}


func main() {
	fmt.Println("Práctica 3 - Seguridad en Redes - Cristina Serrano Trujillo")

	// Instancias
	signup := Signup{}
	login := Login{}
	version := Version{}
	user := User{}
	docs := Docs{}


	// Configurar router
	router := gin.Default()
	router.SetTrustedProxies([]string{"127.0.0.1"})


	// Definir rutas
	router.GET("/version", version.Get)
	router.POST("/signup", signup.SignUp)
	router.POST("/login", login.Login)

	authRoutes := router.Group("/users", AuthorizationMiddleware())
	{
		authRoutes.GET("/users/:user_id", user.Get)              
		authRoutes.GET("/users/:user_id/docs", docs.Get)        
		authRoutes.POST("/users/:user_id/docs/:doc_id", user.Post) 
		authRoutes.PUT("/users/:user_id/docs/:doc_id", user.Put)  
		authRoutes.DELETE("/users/:user_id/docs/:doc_id", user.Delete) 

	}

	// Iniciar servidor
	router.RunTLS("myserver.local:5000", "certs/cert.pem", "certs/key.pem")
}