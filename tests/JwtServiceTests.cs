using System;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using AuthService.Data;
using AuthService.Models;
using AuthService.Services;
using Xunit;

namespace AuthService.Tests
{
    public class JwtServiceTests
    {
        private IConfiguration GetConfiguration()
        {
            var inMemorySettings = new[] {
                new KeyValuePair<string,string>("Jwt:SecretKey", "test-secret-key-that-is-long-enough-123456"),
                new KeyValuePair<string,string>("Jwt:Issuer", "test-issuer"),
                new KeyValuePair<string,string>("Jwt:Audience", "test-audience"),
                new KeyValuePair<string,string>("Jwt:AccessTokenExpiryMinutes", "60")
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
        public void GenerateAccessToken_Returns_Valid_Token_With_Claims()
        {
            // Arrange
            var config = GetConfiguration();
            using var db = GetInMemoryDb();
            var jwtService = new JwtService(config, db);

            var user = new User
            {
                Id = 1,
                Email = "test@example.com",
                FirstName = "Test",
                LastName = "User"
            };

            // Act
            var token = jwtService.GenerateAccessToken(user);

            // Assert
            Assert.False(string.IsNullOrWhiteSpace(token));

            var handler = new JwtSecurityTokenHandler();
            var validations = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidIssuer = config["Jwt:Issuer"],
                ValidAudience = config["Jwt:Audience"],
                IssuerSigningKey = new SymmetricSecurityKey(System.Text.Encoding.ASCII.GetBytes(config["Jwt:SecretKey"]!))
            };

            var principal = handler.ValidateToken(token, validations, out var validatedToken);
            Assert.NotNull(principal);
            Assert.Equal("test@example.com", principal.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Email)?.Value);
            Assert.Equal("1", principal.Claims.FirstOrDefault(c => c.Type == ClaimTypes.NameIdentifier)?.Value);
        }

        [Fact]
        public void GenerateRefreshToken_Returns_Base64String()
        {
            var config = GetConfiguration();
            using var db = GetInMemoryDb();
            var jwtService = new JwtService(config, db);

            var rt = jwtService.GenerateRefreshToken();

            Assert.False(string.IsNullOrWhiteSpace(rt));

            // ensure it's valid base64
            Convert.FromBase64String(rt);
        }

        [Fact]
        public void GetPrincipalFromExpiredToken_Returns_Principal()
        {
            // Arrange
            var config = GetConfiguration();
            using var db = GetInMemoryDb();
            var jwtService = new JwtService(config, db);

            // create a token that is already expired
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = System.Text.Encoding.ASCII.GetBytes(config["Jwt:SecretKey"]!);
            var descriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[] {
                    new Claim(ClaimTypes.NameIdentifier, "42"),
                    new Claim(ClaimTypes.Email, "expired@example.com")
                }),
                Expires = DateTime.UtcNow.AddMinutes(-10),
                Issuer = config["Jwt:Issuer"],
                Audience = config["Jwt:Audience"],
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256)
            };

            var token = tokenHandler.CreateToken(descriptor);
            var tokenString = tokenHandler.WriteToken(token);

            // Act
            var principal = jwtService.GetPrincipalFromExpiredToken(tokenString);

            // Assert
            Assert.NotNull(principal);
            Assert.Equal("42", principal.Claims.First(c => c.Type == ClaimTypes.NameIdentifier).Value);
            Assert.Equal("expired@example.com", principal.Claims.First(c => c.Type == ClaimTypes.Email).Value);
        }
    }
}
