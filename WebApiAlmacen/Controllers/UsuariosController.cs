using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using WebApiAlmacen.DTOs;
using WebApiAlmacen.Models;
using WebApiAlmacen.Services;

namespace WebApiAlmacen.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    [Authorize]
    public class UsuariosController : ControllerBase
    {
        private readonly MiAlmacenContext _context;
        // Para acceder a la clave de encriptación, que está registrada en el appsettings.Development.json
        // necesitamos una dependencia más que llama IConfiguration. Esa configuración en un servicio
        // que tenemos que inyectar en el constructor
        private readonly IConfiguration _configuration;
        // Para encriptar, debemos incorporar otra dependencia más. Se llama IDataProtector. De nuevo, en un servicio
        // que tenemos que inyectar en el constructor
        private readonly IDataProtector _dataProtector;
        // El IDataProtector, para que funcione, lo debemos registrar en el program
        // Mirar en el program la línea: builder.Services.AddDataProtection();
        // Inyectamos el servicio de estión de hashes
        private readonly HashService _hashService;
        public UsuariosController(MiAlmacenContext context, IConfiguration configuration, IDataProtectionProvider dataProtectionProvider, HashService hashService)
        {
            _context = context;
            _configuration = configuration;
            // Con el dataProtector podemos configurar un gestor de encriptación con esta línea
            // dataProtectionProvider.CreateProtector crea el gestor de encriptación y se apoya en la clave
            // de encriptación que tenemos en el appsettings.Development y que hemos llamado ClaveEncriptacion
            _dataProtector = dataProtectionProvider.CreateProtector(configuration["ClaveEncriptacion"]);
            _hashService = hashService;
        }

        [HttpPost("encriptar/nuevousuario")]
        public async Task<ActionResult> PostNuevoUsuario([FromBody] DTOUsuario usuario)
        {
            // Encriptamos el password
            var passEncriptado = _dataProtector.Protect(usuario.Password);
            var newUsuario = new Usuario
            {
                Email = usuario.Email,
                Password = passEncriptado
            };
            await _context.Usuarios.AddAsync(newUsuario);
            await _context.SaveChangesAsync();

            return Ok(newUsuario);
        }

        [HttpPost("encriptar/checkusuario")]
        public async Task<ActionResult> PostCheckUserPassEncriptado([FromBody] DTOUsuario usuario)
        {
            // Esto haría un login con nuestro sistema de encriptación
            // Buscamos si existe el usuario
            var usuarioDB = await _context.Usuarios.FirstOrDefaultAsync(x => x.Email == usuario.Email);
            if (usuarioDB == null)
            {
                return Unauthorized(); // Si el usuario no existe, devolvemos un 401
            }
            // Descencriptamos el password
            var passDesencriptado = _dataProtector.Unprotect(usuarioDB.Password);
            // Y ahora miramos aver si el password de la base de datos que ya hemos encriptado cuando hemos creado el usuario
            // coincide con el que viene en la petición
            if (usuario.Password == passDesencriptado)
            {
                return Ok(); // Devolvemos un Ok si coinciden
            }
            else
            {
                return Unauthorized(); // Devolvemos un 401 si no coinciden
            }
        }


        // Endpoint para registrar un nuevo usuario con contraseña hasheada y salt
        [HttpPost("hash/nuevousuario")]
        public async Task<ActionResult> PostNuevoUsuarioHash([FromBody] DTOUsuario usuario)
        {
            // Generar el hash y salt a partir de la contraseña proporcionada
            var resultadoHash = _hashService.Hash(usuario.Password);

            // Crear una nueva instancia de Usuario con la información proporcionada y el hash/salt generados
            var newUsuario = new Usuario
            {
                Email = usuario.Email,
                Password = resultadoHash.Hash,
                Salt = resultadoHash.Salt
            };

            // Agregar el nuevo usuario a la base de datos
            await _context.Usuarios.AddAsync(newUsuario);
            await _context.SaveChangesAsync();

            // Devolver un resultado satisfactorio con la información del nuevo usuario
            return Ok(newUsuario);
        }

        // Endpoint para verificar las credenciales de un usuario utilizando contraseña hasheada y salt
        [HttpPost("hash/checkusuario")]
        public async Task<ActionResult> CheckUsuarioHash([FromBody] DTOUsuario usuario)
        {
            // Buscar el usuario en la base de datos por su dirección de correo electrónico
            var usuarioDB = await _context.Usuarios.FirstOrDefaultAsync(x => x.Email == usuario.Email);

            // Verificar si el usuario existe
            if (usuarioDB == null)
            {
                // Devolver un resultado no autorizado si el usuario no existe
                return Unauthorized();
            }

            // Generar un hash utilizando el salt almacenado en la base de datos
            var resultadoHash = _hashService.Hash(usuario.Password, usuarioDB.Salt);

            // Verificar si el hash generado coincide con el hash almacenado en la base de datos
            if (usuarioDB.Password == resultadoHash.Hash)
            {
                // Devolver un resultado satisfactorio si las credenciales son válidas
                return Ok();
            }
            else
            {
                // Devolver un resultado no autorizado si las credenciales no son válidas
                return Unauthorized();
            }
        }

        // Endpoint para generar un enlace de cambio de contraseña con hash y salt
        [AllowAnonymous]
        [HttpPost("hash/linkchangepassword")]
        public async Task<ActionResult> LinkChangePasswordHash([FromBody] DTOUsuarioLinkChangePassword usuario)
        {
            // Buscar el usuario en la base de datos por su dirección de correo electrónico (con AsTracking para evitar problemas de rastreo)
            var usuarioDB = await _context.Usuarios.AsTracking().FirstOrDefaultAsync(x => x.Email == usuario.Email);
            if (usuarioDB == null)
            {
                // Devolver un resultado no autorizado si el usuario no existe
                return Unauthorized();
            }

            // Generar un nuevo GUID y convertirlo en un texto para usar como enlace de cambio de contraseña
            Guid miGuid = Guid.NewGuid();
            string textoEnlace = Convert.ToBase64String(miGuid.ToByteArray());
            textoEnlace = textoEnlace.Replace("=", "").Replace("+", "").Replace("/", "").Replace("?", "");

            // Asignar el enlace de cambio de contraseña al usuario y guardar los cambios
            usuarioDB.EnlaceCambioPass = textoEnlace;
            await _context.SaveChangesAsync();

            // Devolver el enlace generado
            return Ok($"https://localhost:7127/changepassword/{textoEnlace}");
        }

        // Endpoint para verificar un enlace de cambio de contraseña con hash y salt
        [HttpGet("/changepassword/{textoEnlace}")]
        public async Task<ActionResult> LinkChangePasswordHash(string textoEnlace)
        {
            // Buscar el usuario en la base de datos por su enlace de cambio de contraseña
            var usuarioDB = await _context.Usuarios.FirstOrDefaultAsync(x => x.EnlaceCambioPass == textoEnlace);
            if (usuarioDB == null)
            {
                // Devolver un resultado incorrecto si el enlace no es válido
                return BadRequest("Enlace incorrecto");
            }

            // Devolver un resultado correcto si el enlace es válido
            return Ok("Enlace correcto");
        }
        // Marca el método como permitido sin autenticación.
        [AllowAnonymous]
        [HttpPost("login")]
        public async Task<ActionResult> Login([FromBody] DTOUsuario usuario)
        {
            // Busca el usuario en la base de datos por su dirección de correo electrónico.
            var usuarioDB = await _context.Usuarios.FirstOrDefaultAsync(x => x.Email == usuario.Email);
            if (usuarioDB == null)
            {
                // Devuelve un resultado BadRequest si el usuario no existe.
                return BadRequest();
            }

            // Genera el hash del password proporcionado y lo compara con el hash almacenado en la base de datos.
            var resultadoHash = _hashService.Hash(usuario.Password, usuarioDB.Salt);
            if (usuarioDB.Password == resultadoHash.Hash)
            {
                // Si el login es exitoso, genera un token y devuelve la respuesta.
                var response = GenerarToken(usuario);
                return Ok(response);
            }
            else
            {
                // Devuelve un resultado BadRequest si las credenciales no son válidas.
                return BadRequest();
            }
        }

        // Método privado para generar un token JWT.
        private DTOLoginResponse GenerarToken(DTOUsuario credencialesUsuario)
        {
            // Los claims son la información que va en el payload del token.
            var claims = new List<Claim>()
    {
        new Claim(ClaimTypes.Email, credencialesUsuario.Email),
        new Claim("lo que yo quiera", "cualquier otro valor")
    };

            // Obtiene la clave secreta para la generación de tokens desde la configuración.
            var clave = _configuration["ClaveJWT"];
            // Construye la clave para firmar el token.
            var claveKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(clave));
            var signinCredentials = new SigningCredentials(claveKey, SecurityAlgorithms.HmacSha256);
            // Configura el token con sus características.
            var securityToken = new JwtSecurityToken(
                claims: claims,
                expires: DateTime.Now.AddDays(30),
                signingCredentials: signinCredentials
            );

            // Convierte el token a cadena para devolverlo en la respuesta.
            var tokenString = new JwtSecurityTokenHandler().WriteToken(securityToken);

            // Devuelve un objeto DTOLoginResponse con el token y el email.
            return new DTOLoginResponse()
            {
                Token = tokenString,
                Email = credencialesUsuario.Email
            };

        }
    }
}


