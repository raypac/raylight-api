using RaylightApi.Domain.Entities.Enums;
using RaylightApi.Domain.Primitives;
using System.Net.Http.Headers;

namespace RaylightApi.Domain.Entities;

public sealed class RefreshTokenVerification : Entity
{
    private RefreshTokenVerification()
    {
    }

    private RefreshTokenVerification(
        Guid id,
        string userId,
        string jti,
        DateTime expiryDateOnUtc,
        RefreshTokenState state) : base(id)
    {
        UserId = userId;
        Jti = jti;
        ExpiryDateOnUtc = expiryDateOnUtc;
        State = state;
    }

    public string UserId { get; private set; }

    public string Jti { get; private set; }

    public DateTime ExpiryDateOnUtc { get; private set; }

    public RefreshTokenState State { get; private set; }

    public static RefreshTokenVerification Create(
        string userId,
        string jti,
        DateTime expiryDateOnUtc,
        RefreshTokenState state,
        Guid id = default)
    {
        if (id == default)
        {
            id = Guid.NewGuid();
        }

        return new RefreshTokenVerification(id, userId, jti, expiryDateOnUtc, state);
    }

}
