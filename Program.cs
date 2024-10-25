/*

//---------------primera version del programa -------------------

using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.OpenApi.Models;
using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.OpenApi.Models; // Asegúrate de incluir esto para Swagger

var builder = WebApplication.CreateBuilder(args);

// Configuración de los servicios para la aplicación
builder.Services.AddControllersWithViews();

// Configuración de Swagger
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo { Title = "Mi API", Version = "v1" });
});

var app = builder.Build();

// Configuración del middleware
if (app.Environment.IsDevelopment())
{
    // Habilitar Swagger solo en el entorno de desarrollo
    app.UseSwagger();
    app.UseSwaggerUI(c =>
    {
        c.SwaggerEndpoint("/swagger/v1/swagger.json", "Mi API v1");
        c.RoutePrefix = string.Empty; // Esto permite que Swagger esté disponible en la ruta raíz
    });
}
else
{
    app.UseExceptionHandler("/Home/Error");
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseAuthorization();

// Definir la ruta predeterminada
app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.Run();

// Clase Persona con valores predeterminados para evitar errores CS8618
public class Persona
{
    public string Nombre { get; set; } = string.Empty;
    public string Apellido { get; set; } = string.Empty;
    public int Edad { get; set; }
    public string Sector { get; set; } = string.Empty;

    public Persona() { }

    public Persona(string nombre, string apellido, int edad, string sector)
    {
        Nombre = nombre;
        Apellido = apellido;
        Edad = edad;
        Sector = sector;
    }
}

public class Estudiante : Persona
{
    public int Matricula { get; set; }

    public Estudiante() { }

    public Estudiante(string nombre, string apellido, int edad, string sector, int matricula)
        : base(nombre, apellido, edad, sector)
    {
        Matricula = matricula;
    }
}

public class Profesor : Persona
{
    public int IdProfesor { get; set; }

    public Profesor() { }

    public Profesor(string nombre, string apellido, int edad, string sector, int idProfesor)
        : base(nombre, apellido, edad, sector)
    {
        IdProfesor = idProfesor;
    }
}

// ----------------------------------------------------- mini jueguito jeje --------------

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;

class Program
{
    static void Main(string[] args)
    {
        // Introducción al juego
        Console.WriteLine("Bienvenido al juego donde tú eres duro/a si adivinas el número, si no, te fuñiste XD");
        
        // Leer el número ganador desde el archivo output.txt
        int numeroGanador = LeerNumeroGanadorDesdeArchivo("output.txt");

        if (numeroGanador == -1)
        {
            Console.WriteLine("Hubo un problema al leer el número ganador. Asegúrate de que el archivo contenga un número válido.");
            return; // Termina la ejecución si hay un error
        }

        // Empezar la adivinanza
        Console.WriteLine("Ahora dime un número del 1 al 10 para adivinar el ganador:");
        int? userGuess = null; // Nullable type para manejar la adivinanza

        while (userGuess != numeroGanador)
        {
            string input = Console.ReadLine();

            // Intentar convertir la entrada a un número entero
            if (int.TryParse(input, out int parsedGuess))
            {
                userGuess = parsedGuess;

                if (userGuess < numeroGanador)
                {
                    Console.WriteLine("Te jodiste, di otro");
                }
                else if (userGuess > numeroGanador)
                {
                    Console.WriteLine("pendejo, dime otro");
                }
                else
                {
                    Console.WriteLine("¡Tú ve! ¡Tú eres duro B)!"); 
                }
            }
            else
            {
                Console.WriteLine("Wey, qué es esa vaina, te dije del 1 al 10.");
            }
        }
    }

    static int LeerNumeroGanadorDesdeArchivo(string path)
    {
        if (!File.Exists(path))
        {
            Console.WriteLine("El archivo no se encontró.");
            return -1; // Indicador de error
        }

        string content = File.ReadAllText(path);
        if (int.TryParse(content.Trim(), out int numeroGanador))
        {
            if (numeroGanador < 1 || numeroGanador > 10)
            {
                Console.WriteLine("El número en el archivo debe estar entre 1 y 10.");
                return -1; // Indicador de error
            }
            return numeroGanador; // Retorna el número ganador
        }
        else
        {
            Console.WriteLine("El contenido del archivo no es un número válido.");
            return -1; // Indicador de error
        }
    }

    // Funciones de ejemplo adicionales
    static void InMemoryStream()
    {
        using (MemoryStream ms = new MemoryStream())
        {
            byte[] data = System.Text.Encoding.UTF8.GetBytes("Memory stream example");
            ms.Write(data, 0, data.Length);
            ms.Seek(0, SeekOrigin.Begin); // Resetear la posición para leer desde el principio
            byte[] buffer = new byte[ms.Length];
            ms.Read(buffer, 0, buffer.Length);
            string result = System.Text.Encoding.UTF8.GetString(buffer);
            Console.WriteLine("Datos del MemoryStream: ");
            Console.WriteLine(result);
        }
    }

    static void WriteFile()
    {
        string path = "output.txt";
        using (FileStream fs = new FileStream(path, FileMode.Create, FileAccess.Write))
        {
            string content = "This is an example of writing to a file using streams.";
            byte[] data = System.Text.Encoding.UTF8.GetBytes(content);
            fs.Write(data, 0, data.Length);  // Índice corregido para empezar en 0
            Console.WriteLine("Datos escritos en el archivo con éxito.");
        }
    }

    static void AddLine()
    {
        string path = "output.txt";
        string content = "This is an example of writing to a file using streams.";
        byte[] data = System.Text.Encoding.UTF8.GetBytes(Environment.NewLine + content);
        using (FileStream fs = new FileStream(path, FileMode.Append, FileAccess.Write, FileShare.None))
        {
            fs.Write(data, 0, data.Length);
        }
    }

    static void ReadFile()
    {
        string path = "output.txt";
        if (File.Exists(path))
        {
            using (FileStream fs = new FileStream(path, FileMode.Open, FileAccess.Read))
            {
                byte[] buffer = new byte[fs.Length];
                fs.Read(buffer, 0, buffer.Length);  // Índice corregido
                string content = System.Text.Encoding.UTF8.GetString(buffer);
                Console.WriteLine("Contenido del archivo: ");
                Console.WriteLine(content);
            }
        }
        else
        {
            Console.WriteLine("Archivo no encontrado.");
        }
    }

    static void SerializeUsersToJson(List<User> users)
    {
        string jsonString = JsonSerializer.Serialize(users, new JsonSerializerOptions { WriteIndented = true });
        File.WriteAllText("users.json", jsonString);
        Console.WriteLine("Lista de usuarios serializada con éxito en archivo JSON.");
    }

    static User FindUserById(int id)
    {
        if (!File.Exists("users.json"))
        {
            Console.WriteLine("Archivo no encontrado.");
            return null!;
        }

        string jsonString = File.ReadAllText("users.json");
        List<User> users = JsonSerializer.Deserialize<List<User>>(jsonString)!;
        User user = users.FirstOrDefault(u => u.Id == id)!;

        if (user != null)
        {
            Console.WriteLine($"Usuario encontrado: {user.Name} ({user.Email})");
        }
        else
        {
            Console.WriteLine("Usuario no encontrado.");
        }

        return user!;
    }
}

public class User
{
    public int Id { get; set; }
    public string Name { get; set; } = string.Empty;
    public string Email { get; set; } = string.Empty;
}
*/

// ----------------------------------------------------- Segunda version del proyecto --------------

using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using DatabaseContextApp;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;

var builder = WebApplication.CreateBuilder(args);

// Configuración de servicios
builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

// Configurar el DbContext
builder.Services.AddDbContext<AppDbContext>(options =>
    options.UseSqlServer(
        "Server=MOISES-DESKTOP;Database=TestDB;Trusted_Connection=true;TrustServerCertificate=True;"
    )
);

// Configurar Swagger con soporte para JWT
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo { Title = "Company App", Version = "v1" });

    c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Name = "Authorization",
        Type = SecuritySchemeType.Http,
        Scheme = "Bearer",
        BearerFormat = "JWT",
        In = ParameterLocation.Header,
        Description = "Introduzca su token JWT.",
    });

    c.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "Bearer",
                },
            },
            new string[] { }
        },
    });
});

// Configurar autenticación JWT
builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        ValidIssuer = "yourdomain.com",
        ValidAudience = "yourdomain.com",
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("vainitaOMGclavelargaysegura_123456")),
    };
});

builder.Services.AddAuthorization();

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();
app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();

string GenerateJwtToken()
{
    var claims = new[]
    {
        new Claim(JwtRegisteredClaimNames.Sub, "test"),
        new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
        new Claim("User", "Mi usuario"),
    };

    var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("vainitaOMGclavelargaysegura_123456"));
    var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

    var token = new JwtSecurityToken(
        issuer: "yourdomain.com",
        audience: "yourdomain.com",
        claims: claims,
        expires: DateTime.Now.AddMinutes(30),
        signingCredentials: creds
    );

    return new JwtSecurityTokenHandler().WriteToken(token);
}

// Ruta para iniciar sesión y generar el token JWT
app.MapPost("/login", (UserLogin login) =>
{
    if (login.Username == "test" && login.Password == "pass") // Validar credenciales
    {
        var token = GenerateJwtToken();
        return Results.Ok(new { token });
    }
    return Results.Unauthorized();
});

app.Run();

// Modelo para recibir las credenciales de usuario en el login
internal class UserLogin
{
    public required string Username { get; set; }
    public required string Password { get; set; }
}


// ----------------------------------------------------- COMING SOON --------------
