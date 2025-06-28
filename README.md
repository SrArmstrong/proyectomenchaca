# Proyecto Menchaca

Proyecto dedicado a la creación de un Sistema de Citas y reportes de un Hospital, aplicando los temas de seguridad, resguardo, avisos de privacidad sobre la información, para la entrega final completa del proyecto de unidad.

## Inicialización del proyecto

go mod init github.com/SrArmstrong/proyectomenchaca

## Ejecutar proyecto y actualizar dependencias

go mod tidy
go run cmd/main.go

## Apis web:

go get github.com/gofiber/fiber/v2

## Endpoints

### Logeo

POST => http://127.0.0.1:6543/login

{
    "correo":"",
    "password":""
}

### Registro

POST => http://127.0.0.1:6543/register

{
    "nombre":"",
    "rol":"",
    "correo":"",
    "telefono":"",
    "especialidad":"",
    "password":""
}