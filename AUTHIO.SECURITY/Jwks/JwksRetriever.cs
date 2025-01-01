using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

namespace AUTHIO.SECURITY.Jwks;

/// <summary>
/// Class to gets configurations of open id connect.
/// </summary>
public class JwksRetriever : IConfigurationRetriever<OpenIdConnectConfiguration>
{
    /// <summary>
    /// Get open Id connection async.
    /// </summary>
    /// <param name="address"></param>
    /// <param name="retriever"></param>
    /// <param name="cancel"></param>
    /// <returns></returns>
    public Task<OpenIdConnectConfiguration> GetConfigurationAsync(
        string address,
        IDocumentRetriever retriever,
        CancellationToken cancel
    ) => GetAsync(
        address,
        retriever,
        cancel
    );

    /// <summary>
    /// Gets the open id connect by url.
    /// </summary>
    /// <param name="address"></param>
    /// <param name="retriever"></param>
    /// <param name="cancel"></param>
    /// <returns></returns>
    public static async Task<OpenIdConnectConfiguration> GetAsync(
        string address,
        IDocumentRetriever retriever,
        CancellationToken cancel
        )
    {
        IdentityModelEventSource.ShowPII = true;

        OpenIdConnectConfiguration openIdConnectConfiguration = new(
            await retriever.GetDocumentAsync(
                address,
                cancel
            )
        );

        JsonWebKeySet jsonWebKeySet = new(
            await retriever.GetDocumentAsync(
                openIdConnectConfiguration.JwksUri, 
                cancel
            )
        );
            
        foreach (SecurityKey signingKey
            in jsonWebKeySet.GetSigningKeys()
            )
        {
            openIdConnectConfiguration
                .SigningKeys
                    .Add(
                        signingKey
                    );
        }

        return openIdConnectConfiguration;
    }
}
