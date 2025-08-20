using RaylightApi.Domain.Common;
using RaylightApi.Domain.Errors;
using RaylightApi.Domain.Primitives;
using System.Text.RegularExpressions;

namespace RaylightApi.Domain.ValueObjects;

public sealed class Email : ValueObject
{
    // Matches: user @example.com
    // Rejects: user @@example, user@.com, spaces, missing @
    private const string EmailPattern = @"^[^\s@]+@[^\s@]+\.[^\s@]+$";

    private Email(string value)
    {
        Value = value;
    }

    public string Value { get; }

    public static Result<Email> Create(string value)
    {
        if (string.IsNullOrEmpty(value))
        {
            return Result.Failure<Email>(DomainErrors.EmailError.Empty);
        }

        if (!Regex.IsMatch(value, EmailPattern))
        {
            return Result.Failure<Email>(DomainErrors.EmailError.Invalid);
        }

        return new Email(value);
    }

    public override IEnumerable<object> GetAtomicValues()
    {
        yield return Value;
    }
}