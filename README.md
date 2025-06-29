# Proyecto Menchaca

Proyecto dedicado a la creación de un Sistema de Citas y reportes de un Hospital, aplicando los temas de seguridad, resguardo, avisos de privacidad sobre la información, para la entrega final completa del proyecto de unidad.

## Características principales
- Autenticación JWT
- Gestión de usuarios (médicos, pacientes, administradores)
- CRUD para consultorios, expedientes, consultas, recetas y horarios
- API REST con Fiber
- PostgreSQL como base de datos
- Variables de entorno para configuración
- Hashing de contraseñas con bcrypt

## Requisitos
- Go 1.24+
- PostgreSQL 15+
- Git (opcional)

## Configuración inicial

1. Clonar el repositorio:

git clone https://github.com/SrArmstrong/proyectomenchaca.git
cd proyectomenchaca


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

## Logica de registro de datos

### Consultorios

#### Endpoint: http://127.0.0.1:6543/api/consultorios

{
  "id_medico": 2,
  "tipo": "privado",
  "ubicacion": "Planta Alta",
  "nombre": "Consultorio 1",
  "telefono": "5551234567"
}


### Expedientes

#### Endpoint: http://127.0.0.1:6543/api/expedientes

{
  "id_paciente": 3,
  "antecedentes": "Asma, hipertensión",
  "historial": "Dos cirugías previas",
  "seguro": "IMSS"
}


### Consultas

#### Endpoint: http://127.0.0.1:6543/api/consultas

{
  "id_consultorio": 1,
  "id_medico": 2,
  "id_paciente": 3,
  "tipo": "general",
  "fecha": "2025-06-28",
  "hora": "10:30",
  "diagnostico": "Dolor de cabeza",
  "costo": 500.0
}

### Recetas

#### Endpoint: http://127.0.0.1:6543/api/recetas

{
  "id_consultorio": 1,
  "id_medico": 2,
  "id_paciente": 3,
  "fecha": "2025-06-28",
  "medicamento": "Paracetamol",
  "dosis": "1 tableta cada 8 horas"
}


### Horarios

#### Endpoint: http://127.0.0.1:6543/api/horarios

{
  "id_consultorio": 1,
  "id_medico": 2,
  "id_consulta": 5,
  "turno": "vespertino",
  "dia": "viernes"
}
