using RaylightApi.Application.Abstractions.Messaging;
using RaylightApi.Application.Abstractions.Persistence;
using RaylightApi.Application.Abstractions.Services;
using RaylightApi.Domain.Entities.Enums;
using RaylightApi.Domain.Events;

namespace RaylightApi.Application.Features.RaylightApi.Events;

internal sealed class MemberPasswordResetEventHandler : IEventHandler<MemberPasswordResetEvent>
{
    private readonly IEmailService _emailService;
    private readonly IMemberIdentityRepository _memberIdentityRepository;

    public MemberPasswordResetEventHandler(IEmailService emailService,
                                     IMemberIdentityRepository memberIdentityRepository)
    {
        _emailService = emailService;
        _memberIdentityRepository = memberIdentityRepository;
    }

    public async Task Handle(MemberPasswordResetEvent notification, CancellationToken cancellationToken)
    {
        var emailVerificationResult = await _memberIdentityRepository
                                                .CreateEmailVerificationAsync(notification.Email, MemberVerificationType.PasswordReset);

        if (emailVerificationResult.IsFailure)
        {
            // TODO: Implement Logging
        }

        await _emailService.SendPasswordResetVerificationAsync(notification.Email, emailVerificationResult.Value);
    }
}