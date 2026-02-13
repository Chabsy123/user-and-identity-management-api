using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using user_and_identity_management_api.Models;

var builder = WebApplication.CreateBuilder(args);

// Configuration
var configuration = builder.Configuration;

// --- Validate connection string early so you get a clear error ---
var defaultConn = configuration.GetConnectionString("DefaultConnection");
if (string.IsNullOrWhiteSpace(defaultConn))
{
    // Helpful explicit error — makes root cause obvious instead of a nested SqlException later
    throw new InvalidOperationException("Connection string 'DefaultConnection' is missing. Check appsettings.json / environment variables.");
}

// Add services to the container.
// for entity framework
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlServer(defaultConn));

// for identity
builder.Services.AddIdentity<IdentityUser, IdentityRole>()
    .AddEntityFrameworkStores<ApplicationDbContext>()
    .AddDefaultTokenProviders();

// authentication (you will likely configure JwtBearer options here)
builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
});

// Add controllers, swagger
builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

// Ensure authentication middleware is added before authorization
app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();
