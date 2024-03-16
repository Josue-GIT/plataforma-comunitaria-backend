package com.gestion.encuesta.controller;

import com.gestion.encuesta.model.Rol;
import com.gestion.encuesta.model.Usuario;
import com.gestion.encuesta.service.UsuarioService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/usuario")
@CrossOrigin("*")
public class UsuarioController {

    @Autowired
    private UsuarioService service;

    @Autowired
    private BCryptPasswordEncoder passwordEncoder;

    @GetMapping("/listar")
    public List<Usuario> listarUsuarios() {
        return service.obtenerTodosLosUsuarios();
    }
    @PostMapping("/guardar")
    public ResponseEntity<?> registrar(@RequestBody Usuario usuario){

        if (usuario.getNombre() == null || usuario.getNombre().isEmpty()) {
            return ResponseEntity.badRequest().body("{\"message\": \"El campo de nombre es obligatorio\"}");
        }


        if (usuario.getApellido() == null || usuario.getApellido().isEmpty()) {
            return ResponseEntity.badRequest().body("{\"message\": \"El campo de apellido es obligatorio\"}");
        }

        if (usuario.getEmail() == null || usuario.getEmail().isEmpty()) {
            return ResponseEntity.badRequest().body("{\"message\": \"El campo de email es obligatorio\"}");
        }

        if (usuario.getUsername() == null || usuario.getUsername().isEmpty()) {
            return ResponseEntity.badRequest().body("{\"message\": \"El campo de username es obligatorio\"}");
        }

        if (usuario.getPassword() == null || usuario.getPassword().isEmpty()) {
            return ResponseEntity.badRequest().body("{\"message\": \"El campo de contraseña es obligatorio\"}");
        }

        if (service.existeUsuarioPorEmail(usuario.getEmail())) {
            return ResponseEntity.badRequest().body("{\"message\": \"El email ya está en uso\"}");
        }

        if (service.existeUsuarioPorUsername(usuario.getUsername())) {
            return ResponseEntity.badRequest().body("{\"message\": \"El username ya está en uso\"}");
        }



        if (usuario.getRol() == null) {
             usuario.setRol(Rol.valueOf("USER"));
         }
    	String username = usuario.getUsername();
        String nombre = usuario.getNombre();
        String apellido = usuario.getApellido();
        String email = usuario.getEmail();
        String contraseñaEncriptada = passwordEncoder.encode(usuario.getPassword());
        usuario.setPassword(contraseñaEncriptada);
        
        Usuario usuarioGuardado = service.guardarUsuario(usuario);

        if (usuarioGuardado != null) {
            return ResponseEntity.ok().body("{\"message\": \"Usuario guardado exitosamente\"}");
        }else {
            return ResponseEntity.badRequest().body("No se pudo guardar el usuario. Verficar campos.");
        }
    }
    @GetMapping("/obtenerUsuarioPorId/{id}")
    public ResponseEntity<?> obtenerUsuarioPorId(@PathVariable Long id) {
        Usuario usuario = service.obtenerUsuarioPorId(id);

        if (usuario != null) {
            return ResponseEntity.ok(usuario);
        } else {
            return ResponseEntity.notFound().build();
        }
    }

    @PutMapping("/vetar/{id}")
    public ResponseEntity<?> vetarUsuario(@PathVariable Long id) {
        Usuario usuario = service.obtenerUsuarioPorId(id);

        if (usuario == null) {
            return ResponseEntity.notFound().build();
        }

        usuario.setVetado(true);
        service.guardarUsuario(usuario);
        return ResponseEntity.ok().body("{\"message\": \"Usuario vetado exitosamente\"}");
    }

    @PutMapping("/quitar-veto/{id}")
    public ResponseEntity<?> quitarVetoUsuario(@PathVariable Long id) {
        Usuario usuario = service.obtenerUsuarioPorId(id);

        if (usuario == null) {
            return ResponseEntity.notFound().build();
        }

        usuario.setVetado(false);
        service.guardarUsuario(usuario);
        return ResponseEntity.ok().body("{\"message\": \"Veto removido exitosamente\"}");
    }
}
