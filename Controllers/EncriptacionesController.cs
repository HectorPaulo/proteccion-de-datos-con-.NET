using System.Security.Cryptography;
using DataProtection.Helpers;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Mvc;

namespace DataProtection.Controllers;


    [ApiController]
    [Route("api/encriptaciones")]
public class EncriptacionesController : ControllerBase
{
    private readonly IDataProtector _protectorEjemplo;
    private readonly ITimeLimitedDataProtector _protectorToken;

    public EncriptacionesController(IDataProtectionProvider dataProtectionProvider)
    {
        _protectorEjemplo = dataProtectionProvider.CreateProtector("Ejemplo");
        _protectorToken = dataProtectionProvider.CreateProtector("Token").ToTimeLimitedDataProtector();
    }

    [HttpGet("encriptar/{textoPlano}")]
    public IActionResult Encriptar(string textoPlano)
    {
        var textoCifrado = _protectorEjemplo.Protect(textoPlano);
        var textoDescifrado = _protectorEjemplo.Unprotect(textoCifrado);

        return Ok(new
        {
            textoPlano,
            textoCifrado,
            textoDescifrado
        });
    }

    [HttpGet("generar-token")]
    public ActionResult GenerarToken()
    {
        var guid = Guid.NewGuid().ToString();
        var token = _protectorToken.Protect(guid, lifetime: TimeSpan.FromHours(12));
        var url = Url.Action("ValidarToken", "Encriptaciones", new { token }, "https");
        return Ok(url);
    }

    [HttpGet("validar-token/{token}", Name = "ValidarToken")]
    public ActionResult ValidarToken(string token)
    {
        try
        {
            _protectorToken.Unprotect(token);
            return Ok(Mensajes.Token.ValidToken);
        }
        catch(CryptographicException)
        {
            return BadRequest(Mensajes.Token.InvalidToken);
        }
    }
}
