using Microsoft.AspNetCore.Mvc.Filters;
namespace WebApiAlmacen.Filters
{
    // Esta clase de filtro de excepciones registra toda la información relevante sobre una excepción en un archivo de texto llamado `logErrores.txt`.
    public class FiltroDeExcepcion : ExceptionFilterAttribute
    {
        // El campo `_env` almacena una referencia al entorno de hospedaje de la aplicación web.
        private readonly IWebHostEnvironment _env;

        // El constructor recibe una referencia al entorno de hospedaje.
        public FiltroDeExcepcion(IWebHostEnvironment env)
        {
            _env = env;
        }

        // El método `OnException()` se ejecuta cuando se produce una excepción no controlada.
        public override void OnException(ExceptionContext context)
        {

            // Obtenemos la ruta del archivo de registro de errores.
            var path = $@"{_env.ContentRootPath}\wwwroot\logErrores.txt";

            // Obtenemos la dirección IP del cliente que solicitó la operación que provocó la excepción.
            var ip = context.HttpContext.Connection.RemoteIpAddress.ToString();

            // Abrimos el archivo de registro de errores en modo de agregación.
            using (StreamWriter writer = new StreamWriter(path, append: true))
            {
                // Escribimos la fuente de la excepción en el archivo de registro.
                writer.WriteLine(context.Exception.InnerException.Source);

                // Escribimos el mensaje de la excepción en el archivo de registro.
                writer.WriteLine(context.Exception.Message);

                // Escribimos la dirección IP del cliente en el archivo de registro.
                writer.WriteLine($"{ip}");
            }

            // Llamamos al método `OnException()` de la clase base para que la excepción se siga manejando de forma normal.
            base.OnException(context);
        }
    }
}
