namespace RaylightApi.Infrastructure.Services;

public class EmailMessage
{
    public List<string> Recipients { get; set; } = [];
    public string Subject { get; set; } = string.Empty;
    public string Body { get; set; } = string.Empty;
    public bool IsBodyHtml { get; set; }
}
