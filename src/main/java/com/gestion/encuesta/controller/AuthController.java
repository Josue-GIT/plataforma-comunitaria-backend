package com.gestion.encuesta.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.gestion.encuesta.model.Credenciales;
import com.gestion.encuesta.model.Usuario;
import com.gestion.encuesta.service.AuthService;

@RestController
@RequestMapping("/api/auth")
@CrossOrigin("*")
public class AuthController {

    @Autowired
    private AuthService authService;

    @Autowired
    private BCryptPasswordEncoder passwordEncoder;
    
    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody Credenciales credenciales) {

        if (credenciales.getUsername() == null || credenciales.getUsername().isEmpty()) {
            return ResponseEntity.badRequest().body("{\"message\": \"El campo de usuario no puede estar vacio\"}");
        }

        if (credenciales.getPassword() == null || credenciales.getPassword().isEmpty()) {
            return ResponseEntity.badRequest().body("{\"message\": \"El campo de contraseña no puede estar vacio\"}");
        }

        String username = credenciales.getUsername();
        String password = credenciales.getPassword();

        Usuario usuarioAutenticado = authService.autenticar(username, password);

        if (usuarioAutenticado != null) {
            if (passwordEncoder.matches(password, usuarioAutenticado.getPassword())) {
                System.out.println("Contraseña válida");
                return ResponseEntity.ok(usuarioAutenticado);
            } else {
                System.out.println("Contraseña no válida");
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Credenciales no válidas");
            }
        } else {
            System.out.println("Usuario no encontrado");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Credenciales no válidas");
        }
    }
}
