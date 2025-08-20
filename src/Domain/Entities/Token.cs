using RaylightApi.Domain.Primitives;

namespace RaylightApi.Domain.Entities;

public sealed class Token : Entity
{
    private Token()
    {
    }

    internal Token(string jwt, 
                   string refreshToken, 
                   DateTime expiryDateOnUtc,
                   Guid id = default) : base(id)
    {
        Jwt = jwt;
        RefreshToken = refreshToken;
        ExpiryDateOnUtc = expiryDateOnUtc;
    }


    public string Jwt { get; private set; }

    public string RefreshToken { get; private set; }

    public DateTime ExpiryDateOnUtc { get; private set; }

    public static Token Create(string jwt, 
                               string refreshToken, 
                               DateTime expiryDateOnUtc, 
                               Guid id = default)
    {
        if (id == default)
        {
            id = Guid.NewGuid();
        }

        return new Token(jwt, refreshToken, expiryDateOnUtc, id);
    }
}