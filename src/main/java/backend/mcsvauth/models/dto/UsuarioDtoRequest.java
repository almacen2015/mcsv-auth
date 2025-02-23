package backend.mcsvauth.models.dto;

public record UsuarioDtoRequest(String username,
                                String password,
                                String email,
                                String nombre,
                                String apellido,
                                String telefono) {
}
