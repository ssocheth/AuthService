using System.ComponentModel.DataAnnotations;

namespace AuthService.Models
{
    public class User
    {
        [Key]
        public int Id { get; set; }
        
        [Required]
        [EmailAddress]
        public string Email { get; set; } = string.Empty;
        
        [Required]
        public string PasswordHash { get; set; } = string.Empty;
        
        public string FirstName { get; set; } = string.Empty;
        public string LastName { get; set; } = string.Empty;
        
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
        public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;

        public bool IsActive { get; set; } = true;
        public string Role { get; set; } = "User"; // Add this line
        
        // Navigation properties
        public virtual ICollection<RefreshToken> RefreshTokens { get; set; } = new List<RefreshToken>();
    }

    public class RefreshToken
    {
        [Key]
        public int Id { get; set; }
        
        [Required]
        public string Token { get; set; } = string.Empty;
        
        public DateTime Expires { get; set; }
        public DateTime Created { get; set; } = DateTime.UtcNow;
        public string CreatedByIp { get; set; } = string.Empty;
        
        public DateTime? Revoked { get; set; }
        public string? RevokedByIp { get; set; }
        public string? ReplacedByToken { get; set; }
        
        public bool IsExpired => DateTime.UtcNow >= Expires;
        public bool IsRevoked => Revoked != null;
        public bool IsActive => !IsRevoked && !IsExpired;
        
        // Foreign key
        public int UserId { get; set; }
        public virtual User User { get; set; } = null!;
    }
}