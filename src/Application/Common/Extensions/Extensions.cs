namespace RaylightApi.Application.Common;

public static class Extensions
{
    public static bool ToBool(this string? value)
    {
        bool.TryParse(value, out var result);

        return result;
    }

    public static int ToInt(this string? value)
    {
        int.TryParse(value, out var result);

        return result;
    }

    public static double ToDouble(this string? value)
    {
        double.TryParse(value, out var result);

        return result;
    }
}
