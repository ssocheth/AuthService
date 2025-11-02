using AuthService.Models;
using BCrypt.Net;

namespace AuthService.Data
{
    public static class DatabaseSeeder
    {
        public static void Seed(AuthDbContext context)
        {
            // Check if admin user already exists
            if (!context.Users.Any(u => u.Email == "admin@example.com"))
            {
                var adminUser = new User
                {
                    Email = "admin@example.com",
                    PasswordHash = BCrypt.Net.BCrypt.EnhancedHashPassword("Admin123!"),
                    FirstName = "System",
                    LastName = "Admin",
                    Role = "Admin",
                    IsActive = true
                };

                context.Users.Add(adminUser);
                context.SaveChanges();
            }
        }
    }
}