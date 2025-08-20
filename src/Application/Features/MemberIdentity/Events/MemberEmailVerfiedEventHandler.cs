using RaylightApi.Application.Abstractions.Messaging;
using RaylightApi.Application.Abstractions.Services;
using RaylightApi.Domain.Events;

namespace RaylightApi.Application.Features.RaylightApi.Events;

internal sealed class MemberEmailVerfiedEventHandler : IEventHandler<MemberEmailVerfiedEvent>
{
    private readonly IEmailService _emailService;

    public MemberEmailVerfiedEventHandler(IEmailService emailService)
    {
        _emailService = emailService;
    }

    public async Task Handle(MemberEmailVerfiedEvent notification, CancellationToken cancellationToken)
    {
        await _emailService.SendEmailVerifiedAsync(notification.Email);
    }
}
