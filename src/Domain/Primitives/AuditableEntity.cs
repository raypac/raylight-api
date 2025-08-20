namespace RaylightApi.Domain.Primitives;

public abstract class AuditableEntity
{
    public string CreatedBy { get; internal set; }

    public DateTime CreatedOnUtc { get; internal set; }

    public string ModifiedBy { get; internal set; }

    public DateTime ModifiedOnUtc { get; internal set; }

    public void SetCreateAuditInfo(string user)
    {
        var utcNow = DateTime.UtcNow;
        CreatedBy = user;
        CreatedOnUtc = utcNow;
        ModifiedBy = user;
        ModifiedOnUtc = utcNow;
    }

    public void SetUpdateAuditInfo(string user)
    {
        var utcNow = DateTime.UtcNow;
        ModifiedBy = user;
        ModifiedOnUtc = utcNow;
    }
}