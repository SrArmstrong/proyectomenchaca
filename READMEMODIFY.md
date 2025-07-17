# Sistema de Gestión Médica - API Documentation

## Descripción General

Esta API REST está desarrollada en Go utilizando el framework Fiber para un sistema de gestión médica. Implementa autenticación JWT con 2FA (TOTP), control de acceso basado en roles y permisos, y gestión completa de usuarios médicos y pacientes.

## Arquitectura

La aplicación sigue una arquitectura modular con separación de responsabilidades:

```
├── internal/
│   ├── handlers/     # Controladores de rutas
│   ├── middleware/   # Middlewares de autenticación y permisos
│   ├── models/       # Estructuras de datos
│   └── utils/        # Utilidades y funciones auxiliares
└── main.go          # Punto de entrada de la aplicación
```

## Características Principales

### 🔐 Seguridad
- **Autenticación JWT** con access tokens (15 min) y refresh tokens (7 días)
- **2FA con TOTP** usando Google Authenticator o aplicaciones similares
- **Validación de contraseñas seguras** (12+ caracteres, mayúsculas, minúsculas, números, símbolos)
- **Rate limiting** (100 requests/minuto)
- **Logs de auditoría** para todas las operaciones

### 👥 Gestión de Usuarios
- **Roles**: admin, medico, paciente
- **Sistema de permisos granular** para cada recurso
- **Registro con generación automática de TOTP**
- **Operaciones CRUD completas**

### 🏥 Gestión Médica
- **Expedientes médicos**
- **Consultorios**
- **Consultas**
- **Horarios**
- **Recetas**

## Base de Datos

Utiliza PostgreSQL (Supabase) con pool de conexiones optimizado:
- Máximo 5 conexiones concurrentes
- Timeouts configurados para evitar conexiones colgadas
- Transacciones para operaciones críticas

## Instalación y Configuración

### Requisitos
- Go 1.21+
- PostgreSQL (recomendado Supabase)
- Variables de entorno configuradas

### Variables de Entorno (.env)
```env
# Base de datos
user=tu_usuario
password=tu_password
host=tu_host
port=5432
dbname=tu_database

# JWT
JWT_SECRET=tu_secreto_jwt_muy_seguro

# Servidor
PORT=3000
```

### Instalación
```bash
# Clonar el repositorio
git clone <repository-url>

# Instalar dependencias
go mod download

# Ejecutar la aplicación
go run main.go
```

## Endpoints de la API

### 🔓 Rutas Públicas (sin autenticación)

#### Registro de Usuario
```http
POST /register
Content-Type: application/json

{
  "nombre": "Dr. Juan Pérez",
  "rol": "medico",
  "correo": "juan@ejemplo.com",
  "telefono": "555-1234",
  "especialidad": "Cardiología",
  "password": "MiPassword123!"
}
```

**Respuesta exitosa:**
```json
{
  "mensaje": "Usuario registrado correctamente",
  "correo": "juan@ejemplo.com",
  "secret": "JBSWY3DPEHPK3PXP",
  "otpauth_url": "otpauth://totp/MiAppSegura:juan@ejemplo.com?secret=JBSWY3DPEHPK3PXP&issuer=MiAppSegura"
}
```

#### Inicio de Sesión
```http
POST /login
Content-Type: application/json

{
  "correo": "juan@ejemplo.com",
  "password": "MiPassword123!",
  "codigo_totp": "123456"
}
```

**Respuesta exitosa:**
```json
{
  "Int_Code": "S",
  "StatusCode": 200,
  "Data": [
    {
      "mensaje": "Inicio de sesión exitoso",
      "timestamp": "2024-01-15T10:30:00Z",
      "tiempo_respuesta": "250ms",
      "access_token": "eyJhbGciOiJIUzI1NiIs...",
      "refresh_token": "eyJhbGciOiJIUzI1NiIs...",
      "permisos": ["read_usuario", "add_consulta"],
      "usuario": {
        "id": 1,
        "nombre": "Dr. Juan Pérez",
        "rol": "medico"
      }
    }
  ]
}
```

#### Refrescar Token
```http
POST /refresh
Content-Type: application/json

{
  "refresh_token": "eyJhbGciOiJIUzI1NiIs..."
}
```

### 🔒 Rutas Protegidas (requieren JWT)

Todas las rutas protegidas requieren el header:
```http
Authorization: Bearer <access_token>
```

#### Cerrar Sesión
```http
POST /api/logout
```

#### Gestión de Usuarios

##### Obtener Médicos
```http
GET /api/usuarios/medicos
Permisos requeridos: read_usuario
```

##### Obtener Pacientes
```http
GET /api/usuarios/pacientes
Permisos requeridos: read_usuario
```

##### Obtener Usuario por ID
```http
GET /api/usuarios/{id}
Permisos requeridos: read_usuario
```

##### Actualizar Usuario
```http
PUT /api/usuarios/{id}
Permisos requeridos: update_usuario
Content-Type: application/json

{
  "nombre": "Dr. Juan Pérez Actualizado",
  "rol": "medico",
  "correo": "juan.nuevo@ejemplo.com",
  "telefono": "555-9876",
  "especialidad": "Cardiología Intervencionista"
}
```

##### Eliminar Usuario
```http
DELETE /api/usuarios/{id}
Permisos requeridos: delete_usuario
```

#### Gestión de Expedientes

##### Obtener Todos los Expedientes
```http
GET /api/expedientes
Permisos requeridos: read_expediente
```

##### Crear Expediente
```http
POST /api/expedientes
Permisos requeridos: add_expediente
Content-Type: application/json

{
  "id_paciente": 1,
  "antecedentes": "Hipertensión arterial",
  "historial": "Consulta inicial por dolor torácico",
  "seguro": "IMSS"
}
```

##### Actualizar Expediente
```http
PUT /api/expedientes/{id}
Permisos requeridos: update_expediente
```

##### Eliminar Expediente
```http
DELETE /api/expedientes/{id}
Permisos requeridos: delete_expediente
```

##### Obtener Expediente por ID
```http
GET /api/expedientes/{id}
Permisos requeridos: read_expediente
```

#### Gestión de Consultorios

##### Crear Consultorio
```http
POST /api/consultorios
Permisos requeridos: add_consultorio
```

##### Obtener Consultorios Disponibles
```http
GET /api/consultorios
Permisos requeridos: read_consultorio
```

##### Obtener Consultorio por ID
```http
GET /api/consultorios/{id}
Permisos requeridos: read_consultorio
```

##### Actualizar Consultorio
```http
PUT /api/consultorios/{id}
Permisos requeridos: update_consultorio
```

##### Eliminar Consultorio
```http
DELETE /api/consultorios/{id}
Permisos requeridos: delete_consultorio
```

#### Gestión de Consultas, Horarios y Recetas

Similar patrón CRUD para:
- **Consultas**: `/api/consultas`
- **Horarios**: `/api/horarios`
- **Recetas**: `/api/recetas`

Cada uno con sus respectivos permisos: `read_`, `add_`, `update_`, `delete_` + nombre del recurso.

## Sistema de Permisos

### Roles Disponibles
- **admin**: Acceso completo a todos los recursos
- **medico**: Acceso a expedientes, consultas, recetas de sus pacientes
- **paciente**: Acceso limitado a su propia información

### Permisos por Recurso
- `read_usuario`, `add_usuario`, `update_usuario`, `delete_usuario`
- `read_expediente`, `add_expediente`, `update_expediente`, `delete_expediente`
- `read_consultorio`, `add_consultorio`, `update_consultorio`, `delete_consultorio`
- `read_consulta`, `add_consulta`, `update_consulta`, `delete_consulta`
- `read_horario`, `add_horario`, `update_horario`, `delete_horario`
- `read_receta`, `add_receta`, `update_receta`, `delete_receta`

## Middleware de Seguridad

### JWTProtected
Valida que el token JWT sea válido y no haya expirado.

### HasPermission
Verifica que el usuario tenga el permiso específico para acceder al recurso.

### Logger
Registra todas las peticiones en la tabla `event_logs` para auditoría.

### Rate Limiter
Limita las peticiones a 100 por minuto por IP.

## Manejo de Errores

La API devuelve respuestas consistentes con el siguiente formato:

### Respuesta Exitosa
```json
{
  "Int_Code": "S",
  "StatusCode": 200,
  "Data": [...]
}
```

### Respuesta de Error
```json
{
  "Int_Code": "E",  // "F" para fallos de validación
  "StatusCode": 400,
  "Data": [
    {
      "mensaje": "Descripción del error",
      "timestamp": "2024-01-15T10:30:00Z",
      "tiempo_respuesta": "50ms"
    }
  ]
}
```

## Códigos de Estado HTTP

- **200**: Operación exitosa
- **201**: Recurso creado exitosamente
- **400**: Datos inválidos o mal formateados
- **401**: No autorizado (token inválido/expirado)
- **403**: Prohibido (sin permisos suficientes)
- **404**: Recurso no encontrado
- **409**: Conflicto (ej. correo ya existe)
- **429**: Demasiadas peticiones
- **500**: Error interno del servidor

## Seguridad Adicional

### Validación de Contraseñas
- Mínimo 12 caracteres
- Al menos 1 mayúscula
- Al menos 1 minúscula
- Al menos 1 número
- Al menos 1 carácter especial (@$!%*#?&)

### Configuración TOTP
- Algoritmo: SHA1
- Dígitos: 6
- Período: 30 segundos
- Skew: 2 (permite códigos con hasta 1 minuto de diferencia)

### Gestión de Tokens
- **Access Token**: 15 minutos de vida
- **Refresh Token**: 7 días de vida
- Los refresh tokens se revocan al hacer logout
- Solo un refresh token activo por usuario

## Logging y Auditoría

Todas las operaciones se registran en la tabla `event_logs` con:
- Endpoint accedido
- Método HTTP
- Usuario que realizó la acción
- Mensaje/resultado
- Dirección IP
- User Agent
- Timestamp

## Consideraciones de Producción

1. **Variables de entorno**: Nunca incluir credenciales en el código
2. **HTTPS**: Siempre usar HTTPS en producción
3. **Rate limiting**: Ajustar según las necesidades
4. **Logs**: Implementar rotación de logs
5. **Monitoreo**: Configurar alertas para errores críticos
6. **Respaldos**: Programar respaldos regulares de la base de datos

## Soporte

Para dudas o problemas:
1. Revisa los logs de la aplicación
2. Verifica la configuración de variables de entorno
3. Consulta la documentación de la base de datos
4. Verifica la conectividad con Supabase