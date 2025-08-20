namespace RaylightApi.Infrastructure.Persistence.Common;

internal static class RandomGenerator
{
    public const int DefaultRandomCharacterLength = 8;
    public const int DefaultRandomNumberLength = 6;
    private const string RandomCharacters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    private const string RandomNumbers = "0123456789";

    public static string RandomNumeric(int length = DefaultRandomNumberLength)
    {
        var random = new Random();
        return new string(Enumerable
            .Repeat(RandomNumbers, length)
            .Select(x => x[random.Next(x.Length)]).ToArray());
    }

    public static string RandomString(int length = DefaultRandomCharacterLength)
    {
        var random = new Random();
        return new string(Enumerable
            .Repeat(RandomCharacters, length)
            .Select(x => x[random.Next(x.Length)]).ToArray());
    }
}