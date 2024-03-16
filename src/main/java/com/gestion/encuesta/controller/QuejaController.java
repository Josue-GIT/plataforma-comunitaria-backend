package com.gestion.encuesta.controller;

import java.util.List;

import com.gestion.encuesta.model.Usuario;
import com.gestion.encuesta.service.UsuarioService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import com.gestion.encuesta.model.QuejaProblema;
import com.gestion.encuesta.service.QuejaService;

@RestController
@RequestMapping("/quejas")
@CrossOrigin("*")
public class QuejaController {
    @Autowired
    private QuejaService quejaService;

    @Autowired
    private UsuarioService usuarioService;

    @GetMapping("/listar")
    public List<QuejaProblema> listarQuejas() {
        return quejaService.obtenerTodasLasQuejas();
    }
    
    @GetMapping("/listar/{id}")
    public ResponseEntity<?> listarQuejaPorId(@PathVariable Long id) {
        QuejaProblema quejaProblema = quejaService.obtenerQuejaPorId(id);
        if (quejaProblema != null){
            return ResponseEntity.ok(quejaProblema);
        }else {
            return ResponseEntity.notFound().build();
        }

    }

    @PostMapping(value = "/guardar", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<?> guardarQueja(@RequestParam("img") String imgString64,
                                          @RequestParam("titulo") String titulo,
                                          @RequestParam("descripcion") String descripcion,
                                          @RequestParam("ubicacion") String ubicacion,
                                          @RequestParam("fechaReporte") String fechaReporte,
                                          @RequestParam("estado") String estado,
                                          @RequestParam("usuarioId") Long usuarioId) {
        try {
            if (imgString64 == null || imgString64.isEmpty()) {
                return ResponseEntity.badRequest().body("La imagen es obligatoria");
            }

            if (titulo == null || titulo.trim().isEmpty()) {
                return ResponseEntity.badRequest().body("El campo título es obligatorio");
            }

            if (descripcion == null || descripcion.trim().isEmpty()) {
                return ResponseEntity.badRequest().body("El campo descripción es obligatorio");
            }

            if (ubicacion == null || ubicacion.trim().isEmpty()) {
                return ResponseEntity.badRequest().body("El campo ubicación es obligatorio");
            }

            if (fechaReporte == null || fechaReporte.trim().isEmpty()) {
                return ResponseEntity.badRequest().body("El campo fecha de reporte es obligatorio");
            }

            if (estado == null || estado.trim().isEmpty()) {
                return ResponseEntity.badRequest().body("El campo estado es obligatorio");
            }

            QuejaProblema queja = new QuejaProblema();
            // Asignar los valores recibidos a los atributos de la queja
            queja.setTitulo(titulo);
            queja.setDescripcion(descripcion);
            queja.setUbicacion(ubicacion);
            queja.setFechaReporte(fechaReporte);
            queja.setEstado(estado);
            queja.setImg(imgString64);
            // Obtener el usuario por su ID y asignarlo a la queja
            Usuario usuario = usuarioService.obtenerUsuarioPorId(usuarioId);
            queja.setUsuario(usuario);

            quejaService.guardarQueja(queja);

            return ResponseEntity.ok().body("{\"message\": \"Queja guardada exitosamente\"}");
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Error al procesar la solicitud: " + e.getMessage());
        }
    }

    @PutMapping(value = "/editar/{id}", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<?> editarQueja(@PathVariable Long id,
                                         @RequestParam("img") String imgString64,
                                         @RequestParam("titulo") String titulo,
                                         @RequestParam("descripcion") String descripcion,
                                         @RequestParam("ubicacion") String ubicacion,
                                         @RequestParam("fechaReporte") String fechaReporte,
                                         @RequestParam("estado") String estado,
                                         @RequestParam("usuarioId") Long usuarioId) {
        try {
            QuejaProblema quejaExistente = quejaService.obtenerQuejaPorId(id);
            if (quejaExistente == null) {
                return ResponseEntity.badRequest().body("La queja a editar no existe");
            }

            if (titulo == null || titulo.trim().isEmpty() ||
                    descripcion == null || descripcion.trim().isEmpty() ||
                    estado == null || estado.trim().isEmpty()) {
                return ResponseEntity.badRequest().body("Los campos Título, descripción y estado no pueden estar vacíos");
            }

            // Actualizar los atributos de la queja existente con los nuevos valores
            quejaExistente.setTitulo(titulo);
            quejaExistente.setDescripcion(descripcion);
            quejaExistente.setUbicacion(ubicacion);
            quejaExistente.setFechaReporte(fechaReporte);
            quejaExistente.setEstado(estado);
            quejaExistente.setImg(imgString64);
            // Obtener el usuario por su ID y asignarlo a la queja
            Usuario usuario = usuarioService.obtenerUsuarioPorId(usuarioId);
            quejaExistente.setUsuario(usuario);

            quejaService.guardarQueja(quejaExistente);

            return ResponseEntity.ok().body("{\"message\": \"Queja editada exitosamente\"}");
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Error al procesar la solicitud: " + e.getMessage());
        }
    }

    @DeleteMapping("/eliminar/{id}")
    public void eliminarQueja(@PathVariable Long id) {
        quejaService.eliminarQuejaPorId(id);
    }
}
