using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using API.Entities;
using API.Interfaces;
using Microsoft.IdentityModel.Tokens;

namespace API.Services
{
    public class TokenService : ITokenService
    {

        //1) we define a private key variable of type SymmetricSecurityKey
        private readonly SymmetricSecurityKey _key;
        //2) we pass the IConfiguration to the constructor in order to use to TokenKey from 
        //the cofig file to genirate the token key from the SymmetricSecurityKey.
        public TokenService(IConfiguration config)
        {
            _key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(config["TokenKey"]));
        }

        public string CreateToken(AppUser user)
        {
            //3 we need to identify the claims which will be put inside the token.
            var claims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.NameId, user.UserName)
            };

            //4 creat the creedentials...
            var creds = new SigningCredentials(_key, SecurityAlgorithms.HmacSha512Signature);

            //5 descripe the token
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims),
                Expires = DateTime.Now.AddDays(7),
                SigningCredentials = creds
            };

            //6 create the token handler
            var tokenHandler = new JwtSecurityTokenHandler();
            var token = tokenHandler.CreateToken(tokenDescriptor);

            //7 return our token from the token handler
            return tokenHandler.WriteToken(token);

        }
    }
}