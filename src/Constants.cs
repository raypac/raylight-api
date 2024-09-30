namespace raylight.api
{
    public static class Constants
    {
        public const string AppName = "Raylight.Jwt";
        public const string AppVersion = "v1";
        public const string Api = "api";
        public const string AllowedUserNameCharacters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._@+";
        public const string RandomCharacters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        public const string RandomNumbers = "0123456789";
        public const string Bearer = nameof(Bearer);
        public const string Unverified = nameof(Unverified);
        public const string Verified = nameof(Verified);

        public const int DefaultRandomCharacterLength = 8;
        public const int DefaultRandomNumberLength = 6;

        public const double DefaultTokenExpiry = 43200D; // 30 Days
        public const double DefaultEmailVerificationExpiry = 1440D; // 1 Day


        //Auth Controller Constants
        public const string Login = nameof(Login);
        public const string Logout = nameof(Logout);
        public const string Refresh = nameof(Refresh);

        //User Controller Constants
        public const string Register = nameof(Register);
        public const string VerifyRegistration = nameof(VerifyRegistration);
        public const string PasswordReset = nameof(PasswordReset);
        public const string PasswordResetVerification = nameof(PasswordResetVerification);
        public const string ChangePassword = nameof(ChangePassword);
        public const string WhoIAm = nameof(WhoIAm);
    }
}
