using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.Filters;
using login_registration.Models;

namespace login_registration.Controllers;

public class HomeController : Controller
{
    private readonly ILogger<HomeController> _logger;
    private MyContext _context;
    public HomeController(ILogger<HomeController> logger, MyContext context)
    {
        _logger = logger;
        _context = context;
    }

    [HttpGet]
    [Route("")]
    public IActionResult Index()
    {
        return View();
    }
    [HttpGet]
    [Route("register")]
    public IActionResult Register()
    {
        return View();
    }

    [HttpPost]
    [Route("users/register")]
    public IActionResult ProcessRegister(User newUser)
    {
        if (ModelState.IsValid)
        {
            PasswordHasher<User> Hasher = new PasswordHasher<User>();
            newUser.Password = Hasher.HashPassword(newUser, newUser.Password);
            _context.Add(newUser);
            _context.SaveChanges();
            return RedirectToAction("Success");
        }
        else
        {
            return View("Index");
        }
    }
    [SessionCheck]
    [HttpGet]
    [Route("users/Success")]
    public IActionResult Success()
    {
        return View("Success");
    }

    [HttpGet]
    [Route("login")]
    public IActionResult Login()
    {
        return View("Index");
    }

    [HttpPost]
    [Route("users/login")]
    public IActionResult ProcessLogin(LoginUser userSubmission)
    {
        if (ModelState.IsValid)
        {
            User userInDb = _context.Users.FirstOrDefault(u => u.Email == userSubmission.EmailLog);

            if (userInDb == null)
            {
                ModelState.AddModelError("EmailLog", "Invalid Email/Password");
                ModelState.AddModelError("PasswordLog", "Invalid Email/Password");
                return View("Index");
            }

            PasswordHasher<LoginUser> hasher = new PasswordHasher<LoginUser>();
            var result = hasher.VerifyHashedPassword(userSubmission, userInDb.Password, userSubmission.PasswordLog);

            if (result == PasswordVerificationResult.Success)
            {
                HttpContext.Session.SetString("Email", userInDb.Email);
                return RedirectToAction("Success");
            }
            else
            {
                ModelState.AddModelError("EmailLog", "Invalid Email/Password");
                ModelState.AddModelError("PasswordLog", "Invalid Email/Password");
                return View("Index");
            }
        }
        else
        {
            return View("Index");
        }
    }

    [HttpPost]
    [Route("logout")]
    public IActionResult ProcessLogout(string logout)
    {
        if (logout == "logout")
        {
            HttpContext.Session.Clear();
            return View("Index");
        }
        return RedirectToAction("Success");
    }

    [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
    public IActionResult Error()
    {
        return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
    }
}

public class SessionCheckAttribute : ActionFilterAttribute
{
    public override void OnActionExecuting(ActionExecutingContext context)
    {
        string? email = context.HttpContext.Session.GetString("Email");

        if (email == null)
        {
            context.Result = new RedirectToActionResult("Login", "Home", null);
        }
    }
}
