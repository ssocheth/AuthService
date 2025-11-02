using AuthService.Data;
using AuthService.Models;
using AuthService.DTOs;
using BCrypt.Net;

namespace AuthService.Services
{
    public interface IAuthService
    {
        Task<DTOs.AuthResponse> RegisterAsync(DTOs.RegisterRequest request, string ipAddress);
        Task<DTOs.AuthResponse> AuthenticateAsync(DTOs.AuthRequest request, string ipAddress);
        Task<DTOs.AuthResponse> RefreshTokenAsync(string refreshToken, string ipAddress);
        Task RevokeTokenAsync(string refreshToken, string ipAddress);
        Task<UserDto> CreateUserAsync(CreateUserRequest request, string currentUserRole);
    }

    public class AuthService : IAuthService
    {
        private readonly AuthDbContext _context;
        private readonly IJwtService _jwtService;
        private readonly IConfiguration _configuration;

        public AuthService(AuthDbContext context, IJwtService jwtService, IConfiguration configuration)
        {
            _context = context;
            _jwtService = jwtService;
            _configuration = configuration;
        }

        public async Task<DTOs.AuthResponse> RegisterAsync(DTOs.RegisterRequest request, string ipAddress)
        {
            // Check if user already exists
            if (_context.Users.Any(u => u.Email == request.Email))
                throw new ArgumentException("User already exists with this email");

            // Create new user
            var user = new User
            {
                Email = request.Email,
                PasswordHash = BCrypt.Net.BCrypt.EnhancedHashPassword(request.Password),
                FirstName = request.FirstName,
                LastName = request.LastName
            };

            _context.Users.Add(user);
            await _context.SaveChangesAsync();

            // Generate tokens
            var accessToken = _jwtService.GenerateAccessToken(user);
            var refreshToken = await GenerateRefreshToken(user, ipAddress);

            return new DTOs.AuthResponse
            {
                AccessToken = accessToken,
                RefreshToken = refreshToken.Token,
                ExpiresAt = DateTime.UtcNow.AddMinutes(Convert.ToDouble(_configuration["Jwt:ExpiryMinutes"])),
                User = new UserDto
                {
                    Id = user.Id,
                    Email = user.Email,
                    FirstName = user.FirstName,
                    LastName = user.LastName
                }
            };
        }

        public async Task<DTOs.AuthResponse> AuthenticateAsync(AuthRequest request, string ipAddress)
        {
            var user = _context.Users.FirstOrDefault(u => u.Email == request.Email);

            if (user == null || !BCrypt.Net.BCrypt.EnhancedVerify(request.Password, user.PasswordHash))
                throw new UnauthorizedAccessException("Invalid credentials");

            if (!user.IsActive)
                throw new UnauthorizedAccessException("Account is deactivated");

            // Generate tokens
            var accessToken = _jwtService.GenerateAccessToken(user);
            var refreshToken = await GenerateRefreshToken(user, ipAddress);

            return new DTOs.AuthResponse
            {
                AccessToken = accessToken,
                RefreshToken = refreshToken.Token,
                ExpiresAt = DateTime.UtcNow.AddMinutes(Convert.ToDouble(_configuration["Jwt:ExpiryMinutes"])),
                User = new UserDto
                {
                    Id = user.Id,
                    Email = user.Email,
                    FirstName = user.FirstName,
                    LastName = user.LastName
                }
            };
        }

        public async Task<DTOs.AuthResponse> RefreshTokenAsync(string refreshToken, string ipAddress)
        {
            var token = _context.RefreshTokens.FirstOrDefault(rt => rt.Token == refreshToken);

            if (token == null)
                throw new ArgumentException("Invalid refresh token");

            if (!token.IsActive)
                throw new ArgumentException("Token is no longer active");

            // Revoke current token
            token.Revoked = DateTime.UtcNow;
            token.RevokedByIp = ipAddress;

            var user = token.User;

            // Generate new tokens
            var newAccessToken = _jwtService.GenerateAccessToken(user);
            var newRefreshToken = await GenerateRefreshToken(user, ipAddress);

            await _context.SaveChangesAsync();

            return new DTOs.AuthResponse
            {
                AccessToken = newAccessToken,
                RefreshToken = newRefreshToken.Token,
                ExpiresAt = DateTime.UtcNow.AddMinutes(Convert.ToDouble(_configuration["Jwt:ExpiryMinutes"])),
                User = new UserDto
                {
                    Id = user.Id,
                    Email = user.Email,
                    FirstName = user.FirstName,
                    LastName = user.LastName
                }
            };
        }

        public async Task RevokeTokenAsync(string refreshToken, string ipAddress)
        {
            var token = _context.RefreshTokens.FirstOrDefault(rt => rt.Token == refreshToken);

            if (token == null)
                throw new ArgumentException("Invalid refresh token");

            if (!token.IsActive)
                throw new ArgumentException("Token is already revoked");

            token.Revoked = DateTime.UtcNow;
            token.RevokedByIp = ipAddress;

            await _context.SaveChangesAsync();
        }

        private async Task<RefreshToken> GenerateRefreshToken(User user, string ipAddress)
        {
            var refreshToken = new RefreshToken
            {
                Token = _jwtService.GenerateRefreshToken(),
                Expires = DateTime.UtcNow.AddDays(Convert.ToDouble(_configuration["Jwt:RefreshTokenExpiryDays"])),
                CreatedByIp = ipAddress,
                UserId = user.Id
            };

            _context.RefreshTokens.Add(refreshToken);
            await _context.SaveChangesAsync();

            return refreshToken;
        }

        public async Task<UserDto> CreateUserAsync(CreateUserRequest request, string currentUserRole = "User")
        {
            // Check if user already exists
            if (_context.Users.Any(u => u.Email == request.Email))
                throw new ArgumentException("User already exists with this email");

            // Only allow setting admin role if current user is admin
            var role = currentUserRole == "Admin" ? request.Role : "User";

            // Create new user
            var user = new User
            {
                Email = request.Email,
                PasswordHash = BCrypt.Net.BCrypt.EnhancedHashPassword(request.Password),
                FirstName = request.FirstName,
                LastName = request.LastName,
                Role = role,
                IsActive = request.IsActive
            };

            _context.Users.Add(user);
            await _context.SaveChangesAsync();

            return new UserDto
            {
                Id = user.Id,
                Email = user.Email,
                FirstName = user.FirstName,
                LastName = user.LastName,
                Role = user.Role,
                IsActive = user.IsActive
            };
        }
    }
}