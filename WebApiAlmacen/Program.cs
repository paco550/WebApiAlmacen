using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using System.Text;
using System.Text.Json.Serialization;
using WebApiAlmacen.Filters;
using WebApiAlmacen.Middlewares;
using WebApiAlmacen.Models;
using WebApiAlmacen.Services;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
// Para evitar, dentro de los Controllers, cuando hacemos consultas de varias tablas (conocidas como join en sql), una referencia infinita entre relaciones
//builder.Services.AddControllers(options =>
//{
//    // Integramos el filtro de excepción para todos los controladores
//    options.Filters.Add(typeof(FiltroDeExcepcion));
//}).AddJsonOptions(options => options.JsonSerializerOptions.ReferenceHandler = ReferenceHandler.IgnoreCycles);

// Para evitar, dentro de los Controllers, cuando hacemos consultas de varias tablas (conocidas como join en sql), una referencia infinita entre relaciones
builder.Services.AddControllers().AddJsonOptions(options => options.JsonSerializerOptions.ReferenceHandler = ReferenceHandler.IgnoreCycles);

// Capturamos del app.settings la cadena de conexión a la base de datos
// Configuration.GetConnectionString va directamente a la propiedad ConnectionStrings y de ahí tomamos el valor de DefaultConnection
var connectionString = builder.Configuration.GetConnectionString("DefaultConnection");
// Nuestros servicios resolverán dependencias de otras clases
// Registramos en el sistema de inyección de dependencias de la aplicación el ApplicationDbContext
// Conseguimos una instancia o configuración global de la base de datos para todo el proyecto
builder.Services.AddDbContext<MiAlmacenContext>(options =>
{
    options.UseSqlServer(connectionString);
    // Esta opción deshabilita el tracking a nivel de proyecto (NoTracking).
    // Por defecto siempre hace el tracking. Con esta configuración, no.
    // En cada operación de modificación de datos en los controladores, deberemos habilitar el tracking en cada operación
    options.UseQueryTrackingBehavior(QueryTrackingBehavior.NoTracking);
}
);

// Gestión de archivos
// Para poder utilizar AddHttpContextAccessor en los controllers o en otros servicios (en nuestro caso, el servicio GestorArchivosLocal)
// Debemos incluir el servicio en el Program de esta manera
builder.Services.AddHttpContextAccessor();
// Nuestro servicio de gestión de Archivos GestorArchivosLocal es un servicio que debemos incluir en el Program para que lo use
// cualquier controlador
builder.Services.AddTransient<GestorArchivosLocal>();
builder.Services.AddDataProtection();
builder.Services.AddTransient<HashService>();


// Configuramos la seguridad en el proyecto. Manifestamos que se va a implementar la seguridad
// mediante JWT firmados por la firma que está en el app.settings.development.json con el nombre ClaveJWT
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
               .AddJwtBearer(options => options.TokenValidationParameters = new TokenValidationParameters
               {
                   ValidateIssuer = false,
                   ValidateAudience = false,
                   ValidateLifetime = true,
                   ValidateIssuerSigningKey = true,
                   IssuerSigningKey = new SymmetricSecurityKey(
                     Encoding.UTF8.GetBytes(builder.Configuration["ClaveJWT"]))
               });


// CORS Policy
builder.Services.AddCors(options =>
{
    options.AddDefaultPolicy(builder =>
    {
        // builder.WithOrigins("https://www.almacenjuanluisusuario.com").WithMethods("GET").AllowAnyHeader();
        // builder.WithOrigins("https://www.almacenjuanluisadmin.com").AllowAnyMethod().AllowAnyHeader();
        builder.AllowAnyOrigin().AllowAnyMethod().AllowAnyHeader();
    });
});

// Agrega el servicio de explorador de extremos para habilitar la generación de documentación sobre los puntos finales de la API.
builder.Services.AddEndpointsApiExplorer();

// Configura el generador Swagger con opciones personalizadas.
builder.Services.AddSwaggerGen(c =>
{
    // Agrega una definición de seguridad llamada "Bearer" para la autenticación mediante JWT.
    c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Name = "Authorization",          // Nombre del campo de la cabecera que contendrá el token.
        Type = SecuritySchemeType.ApiKey, // Tipo de esquema de seguridad (en este caso, ApiKey).
        Scheme = "Bearer",                // Nombre del esquema de seguridad.
        BearerFormat = "JWT",             // Formato esperado del token (en este caso, JWT).
        In = ParameterLocation.Header     // Especifica que el token se debe enviar en la cabecera.
    });

    // Agrega un requisito de seguridad que especifica el uso de la definición "Bearer".
    c.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "Bearer" // Hace referencia a la definición de seguridad "Bearer".
                }
            },
            new string[]{} // Lista vacía de scopes requeridos (en este caso, no se requiere ninguno específicamente).
        }
    });
});

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseCors();

//app.UseMiddleware<LogFileIPMiddleware>();
app.UseMiddleware<LogFileBodyHttpResponseMiddleware>();

// app.UseFileServer();

app.UseAuthorization();

app.MapControllers();

app.Run();
