namespace AUTHIO.SECURITY.Jwks;

/// <summary>
/// Jwk options class.
/// </summary>
public class JwkOptions
{
    /// <summary>
    /// Issuer.
    /// </summary>
    public string Issuer { get; set; }

    /// <summary>
    /// Jwks url.
    /// </summary>
    public string JwksUri { get; set; }

    /// <summary>
    /// Keep for.
    /// </summary>
    public TimeSpan KeepFor { get; set; } = TimeSpan.FromMinutes(15.0);

    /// <summary>
    /// Audience
    /// </summary>
    public string Audience { get; set; }

    /// <summary>
    /// ctor
    /// </summary>
    public JwkOptions()
    {

    }

    /// <summary>
    /// ctor
    /// </summary>
    /// <param name="jwksUri"></param>
    /// <param name="issuer"></param>
    /// <param name="cacheTime"></param>
    /// <param name="audience"></param>
    public JwkOptions(
        string jwksUri,
        string issuer = null,
        TimeSpan? cacheTime = null,
        string audience = null
        )
    {
        JwksUri = jwksUri;
        Uri uri = new(jwksUri);
        Issuer = issuer ?? uri.Scheme + "://" + uri.Authority;
        KeepFor = cacheTime ?? TimeSpan.FromMinutes(15.0);
        Audience = audience;
    }
}
