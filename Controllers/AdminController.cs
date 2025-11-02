using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using AuthService.Services;
using AuthService.DTOs;
using AuthService.Data;

namespace AuthService.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    [Authorize(Roles = "Admin")] // Only admins can access these endpoints
    public class AdminController : ControllerBase
    {
        private readonly IAuthService _authService;
        private readonly AuthDbContext _context;

        public AdminController(IAuthService authService, AuthDbContext context)
        {
            _authService = authService;
            _context = context;
        }

        [HttpPost("users")]
        public async Task<ActionResult<UserDto>> CreateUser(CreateUserRequest request)
        {
            try
            {
                // Get current user's role from claims
                var currentUserRole = User.Claims.FirstOrDefault(c => c.Type == "role")?.Value ?? "User";
                
                var user = await _authService.CreateUserAsync(request, currentUserRole);
                return Ok(user);
            }
            catch (ArgumentException ex)
            {
                return BadRequest(new { message = ex.Message });
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { message = "An error occurred while creating user" });
            }
        }

        [HttpGet("users")]
        public async Task<ActionResult<List<UserDto>>> GetUsers()
        {
            var users = _context.Users
                .Select(u => new UserDto
                {
                    Id = u.Id,
                    Email = u.Email,
                    FirstName = u.FirstName,
                    LastName = u.LastName,
                    Role = u.Role,
                    IsActive = u.IsActive,
                    CreatedAt = u.CreatedAt
                })
                .ToList();

            return Ok(users);
        }

        [HttpPut("users/{id}")]
        public async Task<ActionResult<UserDto>> UpdateUser(int id, UpdateUserRequest request)
        {
            try
            {
                var user = await _context.Users.FindAsync(id);
                if (user == null)
                    return NotFound(new { message = "User not found" });

                // Update allowed fields
                if (!string.IsNullOrEmpty(request.FirstName))
                    user.FirstName = request.FirstName;
                
                if (!string.IsNullOrEmpty(request.LastName))
                    user.LastName = request.LastName;
                
                if (!string.IsNullOrEmpty(request.Role))
                    user.Role = request.Role;
                
                user.IsActive = request.IsActive;
                user.UpdatedAt = DateTime.UtcNow;

                await _context.SaveChangesAsync();

                return Ok(new UserDto
                {
                    Id = user.Id,
                    Email = user.Email,
                    FirstName = user.FirstName,
                    LastName = user.LastName,
                    Role = user.Role,
                    IsActive = user.IsActive
                });
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { message = "An error occurred while updating user" });
            }
        }
    }
}