package com.gestion.encuesta.service;

import com.gestion.encuesta.model.AuthenticationResponse;
import com.gestion.encuesta.model.Rol;
import com.gestion.encuesta.model.Token;
import com.gestion.encuesta.repository.TokenRepository;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.gestion.encuesta.model.Usuario;
import com.gestion.encuesta.repository.UsuarioRepository;

import java.util.List;


@Service
public class AuthService {

    private final UsuarioRepository repository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    private final TokenRepository tokenRepository;

    public AuthService(UsuarioRepository repository, PasswordEncoder passwordEncoder, JwtService jwtService, AuthenticationManager authenticationManager, TokenRepository tokenRepository) {
        this.repository = repository;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
        this.authenticationManager = authenticationManager;
        this.tokenRepository = tokenRepository;
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

        String jwt = jwtService.generateToken(usuario);

        saveUserToken(jwt, usuario);

        return new AuthenticationResponse(jwt);
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

        revokeAllTokensByUser(usuario);

        saveUserToken(token,usuario);

        return new AuthenticationResponse(token);
    }

    private void revokeAllTokensByUser(Usuario usuario) {
        List<Token> validTokenListByUser = tokenRepository.findAllTokenByUser(usuario.getId());
        if (!validTokenListByUser.isEmpty()){
            validTokenListByUser.forEach(t->{
                t.setLoggedOut(true);
            });
        }
        tokenRepository.saveAll(validTokenListByUser);
    }

    private void saveUserToken(String jwt, Usuario usuario) {
        Token token = new Token();
        token.setToken(jwt);
        token.setLoggedOut(false);
        token.setUsuario(usuario);
        tokenRepository.save(token);
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