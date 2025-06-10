package com.edsonsarmiento.authservice.request;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

public class AuthRequest {

    @NotBlank(message = "El campo email es requerido")
    @Email(message = "Formato de correo erroneo")
    String email;

    @NotBlank(message = "El campo password es requerido")
    String password;

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }
}
