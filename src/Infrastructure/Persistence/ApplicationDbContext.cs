using RaylightApi.Domain.Entities.Enums;
using RaylightApi.Infrastructure.Persistence.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;

namespace RaylightApi.Infrastructure.Persistence;

public sealed class ApplicationDbContext : IdentityDbContext
{
    public DbSet<AspNetUserVerification> AspNetUserVerifications { get; set; }

    public DbSet<AspNetRefreshTokenVerification> AspNetRefreshTokenVerification { get; set; }

    public ApplicationDbContext(DbContextOptions options) 
        : base(options)
    {
    }

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);
        SetConversions(builder);
    }

    protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
    {
        base.OnConfiguring(optionsBuilder);
        optionsBuilder
            .UseSeeding((context, _) =>
            {
                var roleCount = context.Set<IdentityRole>().Count();

                if (roleCount == 0)
                {
                    context.Set<IdentityRole>().AddRange(DefaultRoles());
                    context.SaveChanges();
                }
            });
    }

    private static List<IdentityRole> DefaultRoles()
    {
        return
                [
                    new IdentityRole
                    {
                        Name = MemberRoleType.User.ToString(),
                        NormalizedName = MemberRoleType.User.ToString().ToUpper()
                    },
                    new IdentityRole
                    {
                        Name = MemberRoleType.Admin.ToString(),
                        NormalizedName = MemberRoleType.Admin.ToString().ToUpper()
                    }
                ];
    }

    private void SetConversions(ModelBuilder builder)
    {
        var userVerificationTypeConverter = new ValueConverter<MemberVerificationType, string>(
            v => v.ToString(),
            v => (MemberVerificationType)Enum.Parse(typeof(MemberVerificationType), v));

        var userVerificationStateConverter = new ValueConverter<MemberVerificationState, string>(
            v => v.ToString(),
            v => (MemberVerificationState)Enum.Parse(typeof(MemberVerificationState), v));

        var refreshTokenStateConverter = new ValueConverter<RefreshTokenState, string>(
            v => v.ToString(),
            v => (RefreshTokenState)Enum.Parse(typeof(RefreshTokenState), v));


        builder
            .Entity<AspNetUserVerification>()
            .Property(e => e.VerificationType)
            .HasConversion(userVerificationTypeConverter);

        builder
            .Entity<AspNetUserVerification>()
            .Property(e => e.State)
            .HasConversion(userVerificationStateConverter);

        builder
            .Entity<AspNetRefreshTokenVerification>()
            .Property(e => e.State)
            .HasConversion(refreshTokenStateConverter);
    }
}
