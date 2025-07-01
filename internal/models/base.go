package models

type UsuarioLogin struct {
	Correo     string `json:"correo"`
	Password   string `json:"password"`
	CodigoTOTP string `json:"codigo_totp"`
}

type UsuarioRegistro struct {
	Nombre       string `json:"nombre"`
	Rol          string `json:"rol"`
	Correo       string `json:"correo"`
	Telefono     string `json:"telefono"`
	Especialidad string `json:"especialidad"`
	Password     string `json:"password"`
	SecretTOTP   string `json:"secret_totp"`
}

// UsuarioBD representa lo que viene de la base de datos
type UsuarioBD struct {
	ID         int
	Nombre     string
	Password   string
	Rol        string
	SecretTOTP string
}
