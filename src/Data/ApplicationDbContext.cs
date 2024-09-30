using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;
using Microsoft.EntityFrameworkCore;
using raylight.api.Enumerations;
using raylight.api.Models.Entities;

namespace raylight.api.Data
{
    public class ApplicationDbContext : IdentityDbContext
    {
        public virtual DbSet<AspNetRefreshToken> AspNetRefreshTokens { get; set; }

        public virtual DbSet<AspNetUserVerification> AspNetUserVerifications { get; set; }

        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
            : base(options)
        {
        }

        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);
            this.SeedRoles(builder);
            this.SetConversions(builder);
        }

        private void SeedRoles(ModelBuilder builder)
        {
            builder.Entity<IdentityRole>().HasData(
                 new IdentityRole()
                 {
                     Name = UserRoleType.Unverified.ToString(),
                     NormalizedName = UserRoleType.Unverified.ToString().ToUpper()
                 },
                 new IdentityRole()
                 {
                     Name = UserRoleType.Verified.ToString(),
                     NormalizedName = UserRoleType.Verified.ToString().ToUpper()
                 });
        }

        private void SetConversions(ModelBuilder builder)
        {
            var converter = new ValueConverter<UserVerificationType, string>(
                v => v.ToString(),
                v => (UserVerificationType)Enum.Parse(typeof(UserVerificationType), v));

            builder
                .Entity<AspNetUserVerification>()
                .Property(e => e.VerificationType)
                .HasConversion(converter);
        }
    }
}
