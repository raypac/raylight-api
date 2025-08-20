using RaylightApi.Domain.Common;
using RaylightApi.Domain.Errors;
using RaylightApi.Domain.Primitives;
using System.Text.RegularExpressions;

namespace RaylightApi.Domain.ValueObjects;

public sealed class Password : ValueObject
{
    // Has minimum 8 characters in length.Adjust it by modifying {8,}
    // At least one uppercase English letter.You can remove this condition by removing (?=.*?[A - Z])
    // At least one lowercase English letter.You can remove this condition by removing (?=.*?[a - z])
    // At least one digit.You can remove this condition by removing (?=.*?[0 - 9])
    // At least one special character,  You can remove this condition by removing (?=.*?[#?!@$%^&*-])
    private const string PasswordPattern = @"^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[#?!@$%^&*-]).{8,}$";

    private Password(string value)
    {
        Value = value;
    }

    public string Value { get; }

    public static Result<Password> Create(string value)
    {
        if (string.IsNullOrEmpty(value))
        {
            return Result.Failure<Password>(DomainErrors.PasswordError.Empty);
        }

        if (!Regex.IsMatch(value, PasswordPattern))
        {
            return Result.Failure<Password>(DomainErrors.PasswordError.Invalid);
        }

        return new Password(value);
    }

    public override IEnumerable<object> GetAtomicValues()
    {
        yield return Value;
    }
}
