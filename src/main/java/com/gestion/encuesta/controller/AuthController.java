package com.gestion.encuesta.controller;

import com.gestion.encuesta.model.AuthenticationResponse;
import com.gestion.encuesta.model.Rol;
import com.gestion.encuesta.service.UsuarioService;
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

    private final AuthService authService;
    private final UsuarioService service;

    public AuthController(AuthService authService, UsuarioService service) {
        this.authService = authService;
        this.service = service;
    }


    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody Usuario request) {

        if (request.getNombre() == null || request.getNombre().isEmpty()) {
            return ResponseEntity.badRequest().body("{\"message\": \"El campo de nombre es obligatorio\"}");
        }


        if (request.getApellido() == null || request.getApellido().isEmpty()) {
            return ResponseEntity.badRequest().body("{\"message\": \"El campo de apellido es obligatorio\"}");
        }

        if (request.getEmail() == null || request.getEmail().isEmpty()) {
            return ResponseEntity.badRequest().body("{\"message\": \"El campo de email es obligatorio\"}");
        }

        if (request.getUsername() == null || request.getUsername().isEmpty()) {
            return ResponseEntity.badRequest().body("{\"message\": \"El campo de username es obligatorio\"}");
        }

        if (request.getPassword() == null || request.getPassword().isEmpty()) {
            return ResponseEntity.badRequest().body("{\"message\": \"El campo de contraseña es obligatorio\"}");
        }

        if (service.existeUsuarioPorEmail(request.getEmail())) {
            return ResponseEntity.badRequest().body("{\"message\": \"El email ya está en uso\"}");
        }

        if (service.existeUsuarioPorUsername(request.getUsername())) {
            return ResponseEntity.badRequest().body("{\"message\": \"El username ya está en uso\"}");
        }

        return ResponseEntity.ok(authService.register(request));
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody Credenciales credenciales){

        if (credenciales.getUsername() == null || credenciales.getUsername().isEmpty()) {
            return ResponseEntity.badRequest().body("{\"message\": \"El campo de usuario no puede estar vacio\"}");
        }

        if (credenciales.getPassword() == null || credenciales.getPassword().isEmpty()) {
            return ResponseEntity.badRequest().body("{\"message\": \"El campo de contraseña no puede estar vacio\"}");
        }
        Usuario usuario = new Usuario();
        usuario.setUsername(credenciales.getUsername());
        usuario.setPassword(credenciales.getPassword());

        return ResponseEntity.ok(authService.authenticate(usuario));

    }


    /*@PostMapping("/login")
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
    }*/


}
