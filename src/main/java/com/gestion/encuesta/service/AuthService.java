package com.gestion.encuesta.service;

import com.gestion.encuesta.model.AuthenticationResponse;
import com.gestion.encuesta.model.Rol;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.gestion.encuesta.model.Usuario;
import com.gestion.encuesta.repository.UsuarioRepository;

import java.util.Optional;


@Service
public class AuthService {

    private final UsuarioRepository repository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    public AuthService(UsuarioRepository repository, PasswordEncoder passwordEncoder, JwtService jwtService, AuthenticationManager authenticationManager) {
        this.repository = repository;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
        this.authenticationManager = authenticationManager;
    }


    public AuthenticationResponse register (Usuario request) {
        Usuario usuario = new Usuario();
        usuario.setNombre(request.getNombre());
        usuario.setApellido(request.getApellido());
        usuario.setEmail(request.getEmail());
        usuario.setUsername(request.getUsername());
        usuario.setPassword(passwordEncoder.encode(request.getPassword()));

        usuario.setRol(Rol.USER);
        usuario = repository.save(usuario);

        String token = jwtService.generateToken(usuario);
        return new AuthenticationResponse(token);
    }

    public AuthenticationResponse authenticate(Usuario request) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getUsername(),
                        request.getPassword()
                )
        );

        Usuario usuario = repository.findByUsername(request.getUsername()).orElseThrow();
        String token = jwtService.generateToken(usuario);

        return new AuthenticationResponse(token);
    }


    //@Autowired
    //private UsuarioRepository usuarioRepository;

    //@Autowired
    //private BCryptPasswordEncoder passwordEncoder;

    //public Usuario autenticar(String username, String password) {
    //    Usuario usuario = usuarioRepository.findByUsername(username);

    //  if (usuario != null && passwordEncoder.matches(password, usuario.getPassword())) {
    //       return usuario;
    //   } else {
    //      return null;
    //   }
    // }
}