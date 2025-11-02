using Microsoft.AspNetCore.Mvc;
using AuthService.Services;
using AuthService.DTOs;

namespace AuthService.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly IAuthService _authService;

        public AuthController(IAuthService authService)
        {
            _authService = authService;
        }

        [HttpPost("register")]
        public async Task<ActionResult<AuthResponse>> Register(RegisterRequest request)
        {
            try
            {
                var response = await _authService.RegisterAsync(request, GetIpAddress());
                return Ok(response);
            }
            catch (ArgumentException ex)
            {
                return BadRequest(new { message = ex.Message });
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { message = "An error occurred during registration" });
            }
        }

        [HttpPost("login")]
        public async Task<ActionResult<AuthResponse>> Login(AuthRequest request)
        {
            try
            {
                var response = await _authService.AuthenticateAsync(request, GetIpAddress());
                return Ok(response);
            }
            catch (UnauthorizedAccessException)
            {
                return Unauthorized(new { message = "Invalid credentials" });
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { message = "An error occurred during authentication" });
            }
        }

        [HttpPost("refresh-token")]
        public async Task<ActionResult<AuthResponse>> RefreshToken(RefreshTokenRequest request)
        {
            try
            {
                var response = await _authService.RefreshTokenAsync(request.RefreshToken, GetIpAddress());
                return Ok(response);
            }
            catch (ArgumentException ex)
            {
                return BadRequest(new { message = ex.Message });
            }
        }

        [HttpPost("revoke-token")]
        public async Task<IActionResult> RevokeToken(RefreshTokenRequest request)
        {
            try
            {
                await _authService.RevokeTokenAsync(request.RefreshToken, GetIpAddress());
                return Ok(new { message = "Token revoked successfully" });
            }
            catch (ArgumentException ex)
            {
                return BadRequest(new { message = ex.Message });
            }
        }

        private string GetIpAddress()
        {
            if (Request.Headers.ContainsKey("X-Forwarded-For"))
                return Request.Headers["X-Forwarded-For"]!;
            else
                return HttpContext.Connection.RemoteIpAddress?.MapToIPv4().ToString() ?? "unknown";
        }
    }
}