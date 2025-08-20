using Microsoft.EntityFrameworkCore;
using Quartz;
using RaylightApi.Domain.Entities.Enums;
using RaylightApi.Infrastructure.Persistence;

namespace RaylightApi.Infrastructure.BackgroundJobs;

public class ProcessTokenExpiryJob : IJob
{
    private readonly ApplicationDbContext _applicationDbContext;

    public ProcessTokenExpiryJob(
        ApplicationDbContext applicationDbContext)
    {
        _applicationDbContext = applicationDbContext;
    }

    public async Task Execute(IJobExecutionContext context)
    {
        var refreshTokenVerifications = await _applicationDbContext.AspNetRefreshTokenVerification
                                        .Where(x => x.State == RefreshTokenState.Valid)
                                        .Take(10)
                                        .OrderBy(x => x.Id)
                                        .ToListAsync();

        foreach(var refreshToken in refreshTokenVerifications)
        {
            if (DateTime.UtcNow >= refreshToken.ExpiryDateOnUtc)
            {
                refreshToken.State = RefreshTokenState.Expired;
            }
        }

        await _applicationDbContext.SaveChangesAsync();
    }
}