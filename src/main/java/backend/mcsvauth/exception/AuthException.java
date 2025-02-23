package backend.mcsvauth.exception;

public class AuthException extends RuntimeException {
    public static final String USUARIO_NO_ENCONTRADO = "Usuario no encontrado";
    public static final String ROL_NO_ENCONTRADO = "Rol no encontrado";

    public AuthException(String message) {
        super(message);
    }
}
