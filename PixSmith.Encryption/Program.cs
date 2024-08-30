using Microsoft.AspNetCore.Authentication.Certificate;
using Microsoft.AspNetCore.Server.Kestrel.Https;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

builder.Services.AddHttpsRedirection(options =>
{
    options.RedirectStatusCode = 307;
    options.HttpsPort = 44397;
});

builder.Services.AddAuthentication(
        CertificateAuthenticationDefaults.AuthenticationScheme)
    .AddCertificate(options =>
    {
        options.Events = new CertificateAuthenticationEvents
        {
            OnCertificateValidated = ctx =>
            {
                return Task.CompletedTask;
            },

            OnAuthenticationFailed = ctx =>
            {
                return Task.CompletedTask;
            }
        };
    });

builder.WebHost.ConfigureKestrel(o =>
{
    o.ConfigureHttpsDefaults(o =>
        o.ClientCertificateMode = ClientCertificateMode.RequireCertificate);

    o.ConfigureHttpsDefaults(opts =>
    {
        opts.ClientCertificateMode = ClientCertificateMode.RequireCertificate;
        opts.ClientCertificateValidation = (cert, chain, policyErrors) =>
        {
            // Certificate validation logic here
            return true;
        };
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

app.UseAuthorization();

app.MapControllers();

app.Run();
