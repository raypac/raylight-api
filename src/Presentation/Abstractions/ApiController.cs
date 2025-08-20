using MediatR;
using Microsoft.AspNetCore.Mvc;

namespace RaylightApi.Presentation.Abstractions;

public abstract class ApiController : ControllerBase
{
    protected readonly ISender Sender;

    protected ApiController(ISender sender)
    {
        Sender = sender;
    }
}
