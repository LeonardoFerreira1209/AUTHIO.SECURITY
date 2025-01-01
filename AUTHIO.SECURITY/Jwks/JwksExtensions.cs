using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace AUTHIO.SECURITY.Jwks;

/// <summary>
/// Extensions for Jwks.
/// </summary>
public static class JwksExtensions
{
    /// <summary>
    /// Set Jwks options.
    /// </summary>
    /// <param name="options"></param>
    /// <param name="jwkOptions"></param>
    public static void SetJwksOptions(
        this JwtBearerOptions options,
        JwkOptions jwkOptions
        )
    {
        HttpClient httpClient = new(
            options.BackchannelHttpHandler ?? new HttpClientHandler()
            )
        {
            Timeout = options.BackchannelTimeout,
            MaxResponseContentBufferSize = 10485760L
        };

        options.ConfigurationManager = new ConfigurationManager<OpenIdConnectConfiguration>(
            jwkOptions.JwksUri,
            new JwksRetriever(),
            new HttpDocumentRetriever(httpClient)
            {
                RequireHttps = options.RequireHttpsMetadata
            }
        );

        OpenIdConnectConfiguration configuration = 
            options.ConfigurationManager
                .GetConfigurationAsync(CancellationToken.None).Result;

        options.TokenValidationParameters.ValidateIssuer = 
        options.TokenValidationParameters.ValidateAudience = true;
        options.TokenValidationParameters.ValidateIssuer = true;
        options.TokenValidationParameters.ValidateLifetime = true;
        options.TokenValidationParameters.LogValidationExceptions = true;
        options.TokenValidationParameters.ValidateIssuerSigningKey = true;
        options.TokenValidationParameters.ClockSkew = TimeSpan.Zero;
        options.TokenValidationParameters.ValidAudience = jwkOptions.Audience;
        options.TokenValidationParameters.ValidIssuer = configuration.Issuer;
    }
}
