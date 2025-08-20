using RaylightApi.Application.Abstractions.Messaging;
using RaylightApi.Application.Abstractions.Persistence;
using RaylightApi.Application.Abstractions.Services;
using RaylightApi.Domain.Entities.Enums;
using RaylightApi.Domain.Events;

namespace RaylightApi.Application.Features.RaylightApi.Events;

internal sealed class MemberCreatedEventHandler : IEventHandler<MemberCreatedEvent>
{
    private readonly IEmailService _emailService;
    private readonly IMemberIdentityRepository _memberIdentityRepository;

    public MemberCreatedEventHandler(IEmailService emailService,
                                     IMemberIdentityRepository memberIdentityRepository)
    {
        _emailService = emailService;
        _memberIdentityRepository = memberIdentityRepository;
    }

    public async Task Handle(MemberCreatedEvent notification, CancellationToken cancellationToken)
    {
        var emailVerificationResult = await _memberIdentityRepository
                                                .CreateEmailVerificationAsync(notification.Email, MemberVerificationType.EmailConfirmation);

        if (emailVerificationResult.IsFailure)
        {
            // TODO: Implement Logging
        }

        await _emailService.SendEmailVerificationAsync(notification.Email, emailVerificationResult.Value);
    }
}
