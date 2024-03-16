package com.gestion.encuesta.service;

import com.gestion.encuesta.model.Usuario;
import com.gestion.encuesta.repository.UsuarioRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class UsuarioService {

    @Autowired
    UsuarioRepository usuarioRepository;

    public Usuario guardarUsuario(Usuario usuario){
        usuarioRepository.save(usuario);
        return usuario;
    }

    public List<Usuario> obtenerTodosLosUsuarios() {
        return usuarioRepository.findAll();
    }

    public Usuario obtenerUsuarioPorId(Long id) {
        return usuarioRepository.findById(id).orElse(null);
    }

    public boolean existeUsuarioPorUsername(String username) {
        return usuarioRepository.existsByUsername(username);
    }

    public boolean existeUsuarioPorEmail(String email) {
        return usuarioRepository.existsByEmail(email);
    }
}
