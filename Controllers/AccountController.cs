using JwtRoleAuthentication.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Reddit;


namespace JwtRoleAuthentication.Controllers;

[ApiController]
[Route("/api/[controller]")]
public class AccountController : ControllerBase
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly ApplicationDbContext _context;
    private readonly Services.TokenService _tokenService;

    public AccountController(UserManager<Models.ApplicationUser> userManager, ApplicationDbContext context,
        Services.TokenService tokenService, ILogger<AccountController> logger)
    {
        _userManager = userManager;
        _context = context;
        _tokenService = tokenService;
    }


    [HttpPost]
    [Route("register")]
    public async Task<IActionResult> Register(RegistrationRequest request)
    {
        Console.Out.WriteLineAsync("we were before modelstate ");
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }

        Console.Out.WriteLineAsync("we were after modelstate------------------------------------------------------ ");

        var result = await _userManager.CreateAsync(
            new ApplicationUser { UserName = request.Username, Email = request.Email, RefreshToken = _tokenService.GenerateRefreshToken(), RefreshTokenExpiryTime = DateTime.Now.AddDays(7)},
            request.Password!
        );

        if (result.Succeeded)
        {
            request.Password = "";
            return CreatedAtAction(nameof(Register), new { email = request.Email }, request);
        }

        foreach (var error in result.Errors)
        {
            ModelState.AddModelError(error.Code, error.Description);
        }

        return BadRequest(ModelState);
    }


    [HttpPost]
    [Route("login")]
    public async Task<ActionResult<AuthResponse>> Authenticate([FromBody] AuthRequest request)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }

        var managedUser = await _userManager.FindByEmailAsync(request.Email!);

        if (managedUser == null)
        {
            return BadRequest("Bad credentials");
        }

        var isPasswordValid = await _userManager.CheckPasswordAsync(managedUser, request.Password!);

        if (!isPasswordValid)
        {
            return BadRequest("Bad credentials");
        }

        var userInDb = _context.Users.FirstOrDefault(u => u.Email == request.Email);

        if (userInDb is null)
        {
            return Unauthorized();
        }

        var accessToken = _tokenService.CreateToken(userInDb);  
        await _context.SaveChangesAsync();

        return Ok(new Models.AuthResponse
        {
            Username = userInDb.UserName,
            Email = userInDb.Email,
            Token = accessToken,
            RefreshToken = userInDb.RefreshToken,
        });
    }

    [HttpPost("refresh-token")]
    public async Task<IActionResult> RefreshToken([FromBody] TokenModel tokenModel)
    {
        if (tokenModel == null)
            return BadRequest("Invalid client request");

        var user = await _userManager.Users.SingleOrDefaultAsync(u => u.RefreshToken == tokenModel.RefreshToken);
        if (user == null || user.RefreshTokenExpiryTime <= DateTime.Now)
            return BadRequest("Invalid refresh token or token expired");

        var newAccessToken = _tokenService.CreateToken(user);
        var newRefreshToken = _tokenService.GenerateRefreshToken();

        user.RefreshToken = newRefreshToken;
        user.RefreshTokenExpiryTime = DateTime.UtcNow.AddDays(Services.TokenService.RefreshTokenExpirationDays);
        await _userManager.UpdateAsync(user);

        return Ok(new
        {
            accessToken = newAccessToken,
            refreshToken = newRefreshToken,
        });
    }
}


