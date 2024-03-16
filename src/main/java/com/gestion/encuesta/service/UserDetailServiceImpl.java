package com.gestion.encuesta.service;

import com.gestion.encuesta.repository.UsuarioRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class UserDetailServiceImpl implements UserDetailsService {

    private final UsuarioRepository repository;

    public UserDetailServiceImpl(UsuarioRepository repository) {
        this.repository = repository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        System.out.println("Cargando usuario por nombre de usuario: " + username);

        UserDetails userDetails = repository.findByUsername(username)
                .orElseThrow(() -> {
                    System.out.println("Usuario no encontrado para el nombre de usuario: " + username);
                    return new UsernameNotFoundException("No existe el usuario");
                });
        System.out.println("Usuario cargado exitosamente: " + userDetails.getUsername());
        return userDetails;
    }

}

