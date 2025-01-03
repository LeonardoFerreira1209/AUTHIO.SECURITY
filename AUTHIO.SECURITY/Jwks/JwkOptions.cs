namespace AUTHIO.SECURITY.Jwks;

/// <summary>
/// Jwk options class.
/// </summary>
public class JwkOptions
{
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
    /// <param name="jwksUri"></param>
    /// <param name="cacheTime"></param>
    /// <param name="encrypted"></param>
    /// <param name="audience"></param>
    public JwkOptions(
        string jwksUri,
        TimeSpan? cacheTime = null,
        bool encrypted = false,
        string audience = null
        )
    {
        JwksUri = jwksUri;
        Uri uri = new(jwksUri);
        KeepFor = cacheTime ?? TimeSpan.FromMinutes(15.0);
        Audience = audience;
    }
}
