using MediatR;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Net.Http.Headers;
using RaylightApi.Application.Abstractions.Services;
using RaylightApi.Application.Features.RaylightApi.Commands;
using RaylightApi.Presentation.Abstractions;
using RaylightApi.Presentation.Contracts.MemberIdentity;
using System.Security.Claims;

namespace RaylightApi.Presentation.Controllers;

[Route($"{Constant.Api}/[controller]")]
[ApiController]
[Authorize]
public sealed class MemberController : ApiController
{
    private readonly ICurrentUserService _currentUserService;

    public MemberController(
        ISender sender,
        ICurrentUserService currentUserService) 
        : base(sender)
    {
        _currentUserService = currentUserService;
    }

    [AllowAnonymous]
    [HttpPost(Constant.CreateMember)]
    public async Task<IActionResult> CreateMember(
        [FromBody] CreateMemberRequest request,
        CancellationToken cancellationToken)
    {
        var command = new CreateMemberCommand(request.Email, request.Password);

        var result = await Sender.Send(command, cancellationToken);

        if (result.IsFailure)
        {
            return BadRequest(result.Error);
        }

        return CreatedAtAction(
            nameof(CreateMember),
            new { id = result.Value },
            result.Value);
    }

    [AllowAnonymous]
    [HttpPost(Constant.VerifyMemberEmail)]
    public async Task<IActionResult> VerifyMemberEmail(
        [FromBody] VerifyMemberEmailRequest request,
        CancellationToken cancellationToken)
    {
        var command = new VerifyMemberEmailCommand(request.Email, request.Code);

        var result = await Sender.Send(command, cancellationToken);

        if (result.IsFailure)
        {
            return BadRequest(result.Error);
        }

        return CreatedAtAction(
            nameof(VerifyMemberEmail),
            new { id = result.Value },
            result.Value);
    }

    [AllowAnonymous]
    [HttpPost(Constant.Login)]
    public async Task<IActionResult> Login(
        [FromBody] LoginRequest request,
        CancellationToken cancellationToken)
    {
        var command = new MemberLoginCommand(request.Email, request.Password);

        var result = await Sender.Send(command, cancellationToken);

        if (result.IsFailure)
        {
            return BadRequest(result.Error);
        }

        return CreatedAtAction(
            nameof(Login),
            new { id = result.Value },
            result.Value);
    }

    [HttpPost(Constant.Logout)]
    public async Task<IActionResult> Logout(
        [FromBody] LogoutRequest request,
        CancellationToken cancellationToken)
    {
        var command = new MemberLogoutCommand(request.Email);

        var result = await Sender.Send(command, cancellationToken);

        if (result.IsFailure)
        {
            return BadRequest(result.Error);
        }

        return CreatedAtAction(
            nameof(Logout),
            new { id = result.Value },
            result.Value);
    }

    [HttpPost(Constant.RefreshToken)]
    public async Task<IActionResult> RefreshToken(
        [FromBody] RefreshTokenRequest request,
        CancellationToken cancellationToken)
    {
        var accessToken = Request.Headers[HeaderNames.Authorization];

        var jwt = accessToken.FirstOrDefault()?.Replace("Bearer", string.Empty)?.Trim();
        var command = new MemberRefreshTokenCommand(_currentUserService.UserId, jwt, request.RefreshToken);

        var result = await Sender.Send(command, cancellationToken);

        if (result.IsFailure)
        {
            return BadRequest(result.Error);
        }

        return CreatedAtAction(
            nameof(RefreshToken),
            new { id = result.Value },
            result.Value);
    }

    [HttpPost(Constant.ChangePassword)]
    public async Task<IActionResult> ChangePassword(
        [FromBody] ChangePasswordRequest request,
        CancellationToken cancellationToken)
    {
        var accessToken = Request.Headers[HeaderNames.Authorization];

        var jwt = accessToken.FirstOrDefault()?.Replace("Bearer", string.Empty)?.Trim();
        var command = new MemberChangePasswordCommand(_currentUserService.UserId, request.Password, request.NewPassword);

        var result = await Sender.Send(command, cancellationToken);

        if (result.IsFailure)
        {
            return BadRequest(result.Error);
        }

        return CreatedAtAction(
            nameof(ChangePassword),
            new { id = result.Value },
            result.Value);
    }

    [AllowAnonymous]
    [HttpPost(Constant.PasswordReset)]
    public async Task<IActionResult> PasswordReset(
        [FromBody] PasswordResetRequest request,
        CancellationToken cancellationToken)
    {
        var command = new MemberPasswordResetCommand(request.Email);

        var result = await Sender.Send(command, cancellationToken);

        if (result.IsFailure)
        {
            return BadRequest(result.Error);
        }

        return CreatedAtAction(
            nameof(PasswordReset),
            new { id = result.Value },
            result.Value);
    }

    [AllowAnonymous]
    [HttpPost(Constant.VerifyPasswordReset)]
    public async Task<IActionResult> VerifyPasswordReset(
        [FromBody] VerifyResetPasswordRequest request,
        CancellationToken cancellationToken)
    {
        var command = new VerifyMemberPasswordResetCommand(request.Email, request.NewPassword, request.Code);

        var result = await Sender.Send(command, cancellationToken);

        if (result.IsFailure)
        {
            return BadRequest(result.Error);
        }

        return CreatedAtAction(
            nameof(PasswordReset),
            new { id = result.Value },
            result.Value);
    }

    [HttpGet(Constant.WhoIAm)]
    public async Task<IActionResult> WhoIAm()
    {
        var user = HttpContext.User;

        if (user != null)
        {
            var email = user.Claims
                .FirstOrDefault(x => x.Type == ClaimTypes.Email).Value;

            var result = $"WhoIAm-HttpContext.User: {email}" + Environment.NewLine +
                         $"WhoIAm-CurrentUserService.UserId: {_currentUserService.UserId}";
            return Ok(result);
        }

        return BadRequest("Bad Request");
    }
}