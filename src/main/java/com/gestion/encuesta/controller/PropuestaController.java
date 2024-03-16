package com.gestion.encuesta.controller;

import java.util.List;

import com.gestion.encuesta.model.Usuario;
import com.gestion.encuesta.service.UsuarioService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import com.gestion.encuesta.model.Propuesta;
import com.gestion.encuesta.service.PropuestaService;

@RestController
@RequestMapping("/propuestas")
@CrossOrigin("*")
public class PropuestaController {

    @Autowired
    private PropuestaService propuestaService;

    @Autowired
    private UsuarioService usuarioService;

    @GetMapping("/listar")
    public List<Propuesta> listarPropuestas() {
        return propuestaService.obtenerTodasLasPropuestas();
    }

    @GetMapping("/listar/{id}")
    public ResponseEntity<?> listarPropuestaPorId(@PathVariable Long id) {
        Propuesta propuesta = propuestaService.obtenerPropuestaPorId(id);
        if (propuesta != null) {
            return ResponseEntity.ok(propuesta);
        } else {
            return ResponseEntity.notFound().build();
        }
    }

    @PostMapping(value = "/guardar", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<?> guardarPropuesta(@RequestParam("img") String imgString64,
                                              @RequestParam("titulo") String titulo,
                                              @RequestParam("descripcion") String descripcion,
                                              @RequestParam("ubicacion") String ubicacion,
                                              @RequestParam("usuarioId") Long usuarioId) {
        try {

            // Validar campo imagen
            if (imgString64 == null || imgString64.isEmpty()) {
                return ResponseEntity.badRequest().body("La imagen es obligatoria");
            }


            // Validar campo título
            if (titulo == null || titulo.trim().isEmpty()) {
                return ResponseEntity.badRequest().body("El campo título es obligatorio");
            }

            // Validar campo descripción
            if (descripcion == null || descripcion.trim().isEmpty()) {
                return ResponseEntity.badRequest().body("El campo descripción es obligatorio");
            }

            // Validar campo ubicación
            if (ubicacion == null || ubicacion.trim().isEmpty()) {
                return ResponseEntity.badRequest().body("El campo ubicación es obligatorio");
            }

            // Aquí puedes obtener el usuario por su ID
            Usuario usuario = usuarioService.obtenerUsuarioPorId(usuarioId);
            if (usuario == null) {
                return ResponseEntity.badRequest().body("El usuario con ID " + usuarioId + " no existe");
            }

            Propuesta propuesta = new Propuesta();
            propuesta.setTitulo(titulo);
            propuesta.setDescripcion(descripcion);
            propuesta.setUbicacion(ubicacion);
            propuesta.setImg(imgString64);
            propuesta.setUsuario(usuario); // Asignar el usuario a la propuesta
            propuestaService.guardarPropuesta(propuesta);

            return ResponseEntity.ok().body("{\"message\": \"Propuesta guardada exitosamente\"}");
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Error al procesar la solicitud: " + e.getMessage());
        }
    }

    @PutMapping(value = "/editar/{id}", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<?> editarPropuesta(@PathVariable Long id,
                                             @RequestParam("img") String imgString64,
                                             @RequestParam("titulo") String titulo,
                                             @RequestParam("descripcion") String descripcion,
                                             @RequestParam("ubicacion") String ubicacion,
                                             @RequestParam("usuarioId") Long usuarioId) {
        try {
            Propuesta propuestaExistente = propuestaService.obtenerPropuestaPorId(id);
            if (propuestaExistente == null) {
                return ResponseEntity.badRequest().body("La propuesta a editar no existe");
            }

            if (titulo == null || titulo.trim().isEmpty() ||
                    descripcion == null || descripcion.trim().isEmpty() ||
                    ubicacion == null || ubicacion.trim().isEmpty()) {
                return ResponseEntity.badRequest().body("Los campos título, descripcion y ubicación no pueden estar vacíos");
            }

            // Aquí puedes obtener el usuario por su ID
            Usuario usuario = usuarioService.obtenerUsuarioPorId(usuarioId);
            if (usuario == null) {
                return ResponseEntity.badRequest().body("El usuario con ID " + usuarioId + " no existe");
            }

            propuestaExistente.setTitulo(titulo);
            propuestaExistente.setDescripcion(descripcion);
            propuestaExistente.setUbicacion(ubicacion);
            propuestaExistente.setImg(imgString64);
            propuestaExistente.setUsuario(usuario); // Asignar el usuario a la propuesta
            propuestaService.guardarPropuesta(propuestaExistente);

            return ResponseEntity.ok().body("{\"message\": \"Propuesta editada exitosamente\"}");
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Error al procesar la solicitud: " + e.getMessage());
        }
    }

    @DeleteMapping("/eliminar/{id}")
    public ResponseEntity<?> eliminarPropuesta(@PathVariable Long id) {
        Propuesta propuestaExistente = propuestaService.obtenerPropuestaPorId(id);
        if (propuestaExistente == null) {
            return ResponseEntity.badRequest().body("La propuesta a eliminar no existe");
        }

        propuestaService.eliminarPropuestaPorId(id);
        return ResponseEntity.ok().body("{\"message\": \"Propuesta eliminada exitosamente\"}");
    }
}