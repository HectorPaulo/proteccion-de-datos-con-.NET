namespace DataProtection.Helpers;

public class Mensajes
{
    public class Token
    {
        public const string ValidToken = "Token validado";
        public const string InvalidToken = "El token no es válido o ha expirado";
    }

    public class Email
    {
        public const string EmailSent = "Email enviado correctamente";
        public const string EmailError = "Error al enviar el email";
    }
}