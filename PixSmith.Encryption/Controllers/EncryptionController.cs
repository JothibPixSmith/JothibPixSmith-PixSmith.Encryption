using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using NSec.Cryptography;
using System.Security.Cryptography;
using System.Text;

namespace PixSmith.Encryption.Controllers
{
    [Authorize]
    [ApiController]
    [Route("api/[controller]/[action]")]
    public class EncryptionController : ControllerBase
    {
        private readonly ILogger<EncryptionController> _logger;

        public EncryptionController(ILogger<EncryptionController> logger)
        {
            _logger = logger;
        }

        [HttpGet(Name = "GetPbkdf2")]
        public (string salt, string pbkdf2String) GetPbkdf2([FromQuery] string input)
        {
            var randomNumberGernator = RandomNumberGenerator.Create();

            byte[] buffer = new byte[64];

            randomNumberGernator.GetBytes(buffer);

            var salt = BitConverter.ToString(buffer);

            var pbkdf2String = Rfc2898DeriveBytes.Pbkdf2(
                Encoding.Unicode.GetBytes(input),
                Encoding.Unicode.GetBytes(salt),
                600000,
                HashAlgorithmName.SHA256,
                32);

            return (salt, Encoding.Unicode.GetString(pbkdf2String));
        }

        [HttpGet(Name = "GetPbkdf2WithSalt")]
        public string GetPbkdf2WithSalt([FromQuery] string input, [FromQuery] string salt)
        {
            var pbkdf2String = Rfc2898DeriveBytes.Pbkdf2(
                Encoding.Unicode.GetBytes(input),
                Encoding.Unicode.GetBytes(salt),
                600000,
                HashAlgorithmName.SHA256,
                32);

            return Encoding.Unicode.GetString(pbkdf2String);
        }

        [HttpGet(Name = "GetArgon2i")]
        public (string salt, string derivedInput) GetArgon2i([FromQuery] string input)
        {
            var argong2id = new Argon2id(new Argon2Parameters
            {
                MemorySize = 12288,
                NumberOfPasses = 3,
                DegreeOfParallelism = 1,
            });

            var randomNumberGernator = RandomNumberGenerator.Create();

            byte[] buffer = new byte[64];

            randomNumberGernator.GetBytes(buffer);

            var salt = BitConverter.ToString(buffer);

            var result = argong2id.DeriveBytes(input, buffer, 32);

            return (salt, Encoding.Unicode.GetString(result));
        }

        [HttpGet(Name = "GetArgon2iWithSalt")]
        public string GetArgon2iWithSalt([FromQuery] string input, [FromQuery] string salt)
        {
            var argong2id = new Argon2id(new Argon2Parameters
            {
                MemorySize = 12288,
                NumberOfPasses = 3,
                DegreeOfParallelism = 1,
            });

            var saltAsBytes = Encoding.Unicode.GetBytes(salt);

            var result = argong2id.DeriveBytes(saltAsBytes, saltAsBytes, 32);

            return Encoding.Unicode.GetString(result);
        }


    }
}
