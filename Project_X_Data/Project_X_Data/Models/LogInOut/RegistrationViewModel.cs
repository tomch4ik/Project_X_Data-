using System.ComponentModel.DataAnnotations;

namespace Project_X_Data.Models.LogInOut
{
    public class RegistrationViewModel
    {
        [Required(ErrorMessage = "First name is required")]
        public string FirstName { get; set; } = null!;

        [Required(ErrorMessage = "Last name is required")]
        public string LastName { get; set; } = null!;

        [Required(ErrorMessage = "Email is required")]
        [EmailAddress(ErrorMessage = "Invalid email format")]
        public string Email { get; set; } = null!;

        public string? WorkingPlace { get; set; }
        public string? Location { get; set; }

        [Required]
        public DateTime BirthDate { get; set; }

        public IFormFile ProfileImageUrl { get; set; } = null!;

        [Required(ErrorMessage = "Password is required")]
        [RegularExpression(
            @"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).{8,}$",
            ErrorMessage = "Password must be at least 8 characters long, contain upper and lower case letters, a number, and a special character."
        )]
        public string Password { get; set; } = null!;

        [Required(ErrorMessage = "Confirm password is required")]
        [Compare("Password", ErrorMessage = "Passwords do not match")]
        public string ConfirmPassword { get; set; } = null!;
    }
}

