
namespace raylight.api.Helpers
{
    public static class RandomGenerator
    {
        public static string RandomString(int length)
        {
            var random = new Random();
            return new string(Enumerable
                .Repeat(Constants.RandomCharacters, length)
                .Select(x => x[random.Next(x.Length)]).ToArray());
        }

        public static string RandomNumeric(int length)
        {
            var random = new Random();
            return new string(Enumerable
                .Repeat(Constants.RandomNumbers, length)
                .Select(x => x[random.Next(x.Length)]).ToArray());
        }
    }
}
