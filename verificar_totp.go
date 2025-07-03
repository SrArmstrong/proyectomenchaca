package main

import (
	"fmt"
	"time"

	"github.com/pquerna/otp/totp"
)

func main() {
	secret := "2OEEPPJZZOIRKQVXPJ4QHNK4KWZ6JISS"
	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		panic(err)
	}
	fmt.Println("Código TOTP actual:", code)
}
