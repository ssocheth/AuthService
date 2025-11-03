using System;
using System.Linq;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using AuthService.Data;
using AuthService.Models;
using AuthService.Services;
using AuthService.DTOs;
using Xunit;

namespace AuthService.Tests
{
    // Minimal fake JwtService since AuthService requires IJwtService but CreateUserAsync doesn't use it
    internal class FakeJwtService : IJwtService
    {
        public string GenerateAccessToken(User user) => "fake-token";
        public string GenerateRefreshToken() => "fake-refresh";
        public System.Security.Claims.ClaimsPrincipal GetPrincipalFromExpiredToken(string token) => throw new NotImplementedException();
    }

    public class AuthServiceCreateUserTests
    {
        private IConfiguration GetConfiguration()
        {
            var inMemorySettings = new[] {
                new KeyValuePair<string,string>("Jwt:SecretKey", "test-secret-key-that-is-long-enough-123456"),
                new KeyValuePair<string,string>("Jwt:Issuer", "test-issuer"),
                new KeyValuePair<string,string>("Jwt:Audience", "test-audience"),
                new KeyValuePair<string,string>("Jwt:AccessTokenExpiryMinutes", "60"),
                new KeyValuePair<string,string>("Jwt:RefreshTokenExpiryDays", "7"),
                new KeyValuePair<string,string>("Jwt:ExpiryMinutes", "60")
            };

            return new ConfigurationBuilder()
                .AddInMemoryCollection(inMemorySettings)
                .Build();
        }

        private AuthDbContext GetInMemoryDb()
        {
            var options = new DbContextOptionsBuilder<AuthDbContext>()
                .UseInMemoryDatabase(Guid.NewGuid().ToString())
                .Options;
            return new AuthDbContext(options);
        }

        [Fact]
        public async System.Threading.Tasks.Task CreateUser_DefaultRole_When_NotAdmin()
        {
            var config = GetConfiguration();
            using var db = GetInMemoryDb();
            var authService = new AuthService(db, new FakeJwtService(), config);

            var request = new CreateUserRequest
            {
                Email = "newuser@example.com",
                Password = "Password123!",
                FirstName = "New",
                LastName = "User",
                Role = "Admin",
                IsActive = true
            };

            var result = await authService.CreateUserAsync(request, currentUserRole: "User");

            Assert.NotNull(result);
            Assert.Equal("newuser@example.com", result.Email);
            // Because current user is not admin, role should be set to "User"
            Assert.Equal("User", result.Role);

            var persisted = db.Users.FirstOrDefault(u => u.Email == "newuser@example.com");
            Assert.NotNull(persisted);
            Assert.Equal("User", persisted.Role);
        }

        [Fact]
        public async System.Threading.Tasks.Task CreateUser_Allows_AdminRole_When_CallerIsAdmin()
        {
            var config = GetConfiguration();
            using var db = GetInMemoryDb();
            var authService = new AuthService(db, new FakeJwtService(), config);

            var request = new CreateUserRequest
            {
                Email = "adminuser@example.com",
                Password = "Password123!",
                FirstName = "Admin",
                LastName = "User",
                Role = "Admin",
                IsActive = true
            };

            var result = await authService.CreateUserAsync(request, currentUserRole: "Admin");

            Assert.NotNull(result);
            Assert.Equal("Admin", result.Role);

            var persisted = db.Users.FirstOrDefault(u => u.Email == "adminuser@example.com");
            Assert.NotNull(persisted);
            Assert.Equal("Admin", persisted.Role);
        }

        [Fact]
        public async System.Threading.Tasks.Task CreateUser_Throws_On_DuplicateEmail()
        {
            var config = GetConfiguration();
            using var db = GetInMemoryDb();
            // seed a user
            db.Users.Add(new User { Email = "dup@example.com", PasswordHash = "x", FirstName = "D", LastName = "U" });
            await db.SaveChangesAsync();

            var authService = new AuthService(db, new FakeJwtService(), config);

            var request = new CreateUserRequest
            {
                Email = "dup@example.com",
                Password = "Password123!",
                FirstName = "New",
                LastName = "User",
                Role = "User",
                IsActive = true
            };

            await Assert.ThrowsAsync<ArgumentException>(async () => await authService.CreateUserAsync(request, "Admin"));
        }
    }
}
