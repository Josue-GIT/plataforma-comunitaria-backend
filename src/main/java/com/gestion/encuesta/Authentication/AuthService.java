package com.gestion.encuesta.Authentication;

import com.gestion.encuesta.jwt.JwtService;
import com.gestion.encuesta.model.Rol;
import com.gestion.encuesta.model.Usuario;
import com.gestion.encuesta.repository.UsuarioRepository;
import com.gestion.encuesta.service.RolService;
import lombok.RequiredArgsConstructor;
import org.apache.catalina.User;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final JwtService jwtService;
    private final RolService rolService;
    private final UsuarioRepository usuarioRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;

    public AuthResponse login(LoginRequest request) {
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(request.getUsername(),request.getPassword()));
        Usuario user = usuarioRepository.findByUsername(request.getUsername()).orElseThrow(null);
        String token = jwtService.getToken(user);
        return AuthResponse.builder()
                .token(token)
                .build();
    }

    public AuthResponse register(RegisterRequest request) {
        Long rol = 1L;
        Usuario usuario = Usuario.builder()
                .username(request.getUsername())
                .password(passwordEncoder.encode(request.getPassword()))
                .nombre(request.getNombre())
                .apellido(request.getApellido())
                .email(request.getEmail())
                .rol(rolService.getRolById(rol).orElseThrow())
                .build();
        usuarioRepository.save(usuario);


        return AuthResponse.builder()
                .token(jwtService.getToken(usuario))
                .build();
    }

}