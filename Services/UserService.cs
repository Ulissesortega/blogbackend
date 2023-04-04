using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using blogbackend.Models;
using blogbackend.Models.DTO;
using blogbackend.Services.Context;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Text;
using System.Security.Claims;

namespace blogbackend.Services
{
    public class UserService : ControllerBase
    {
        private readonly DataContext _context;
        public UserService(DataContext context)
        {
            _context = context;
        }


        public bool DoesUserExist(string? Username)
        {
            // check the table to see if the username exist
            // if 1 item matches the condition, return the item
            //if no item mtaches the condition, return null
            //if multiple item matches, an error will occur

            
            
            return _context.UserInfo.SingleOrDefault(user => user.Username == Username) != null;

                    //object != null; true
                    //null != null; false

        }
          public bool AddUser(CreateAccountDTO UserToAdd)
            {
            //if the user already exist
            //if they do not exist we can then have the account to be created
            bool result = false;
            if(!DoesUserExist(UserToAdd.Username))
            {
                // the user does not exist
                // creating a new instance of user model (empty object)
                UserModel newUser = new UserModel();
                //create our salt and hash password
                var hashPassword = HashPassword(UserToAdd.Password);
                newUser.Id = UserToAdd.Id;
                newUser.Username = UserToAdd.Username;
                newUser.Salt = hashPassword.Salt;
                newUser.Hash = hashPassword.Hash;
                //adding new user to our database
                _context.Add(newUser);
                //this saves to our database and returns the numbers of entries that was written to the database
                //_context.SaveChanges();
                result = _context.SaveChanges() != 0;
            }

            return result;
            //else throw a false
            }

            public PasswordDTO HashPassword(string? password)
            {
                PasswordDTO newHashedPassword = new PasswordDTO();
                //this is a byte array with a lenght of 64
                byte[] SaltByte = new byte[64];
                var provider = new RNGCryptoServiceProvider();
                // enhance rng of numbers without using zero
                provider.GetNonZeroBytes(SaltByte);
                // enconding the 64 digits to string
                // salt makes the hash unique to the user
                // if we only had a hash passsword, if people has the same password. the hash would be the same
                var Salt = Convert.ToBase64String(SaltByte);
                Rfc2898DeriveBytes rfc2898DeriveBytes = new Rfc2898DeriveBytes(password, SaltByte, 10000);
                //encoding our password with our salt
                // if anyone would to brute force this, it will take a decades
                var Hash = Convert.ToBase64String(rfc2898DeriveBytes.GetBytes(256));

                newHashedPassword.Salt = Salt;
                newHashedPassword.Hash = Hash;

                return newHashedPassword;
            }

            public bool VerifyUserPassword(string? Password, string? storedHash, string? storedSalt)
            {
               // get our existing salt and chnage it to base 64 string
               var SaltBytes = Convert.FromBase64String(storedSalt);
               //making a password that the user inputed and using the stored salt
               var rfc2898DeriveBytes = new Rfc2898DeriveBytes(Password, SaltBytes, 10000);
                //Created the new hash
               var newHash = Convert.ToBase64String(rfc2898DeriveBytes.GetBytes(256));
               //checking if the new has is the same as the stored hash
               return newHash == storedHash;
            }

            public IActionResult Login(LoginDTO User)
            {
                //want to return an error code if the user ford noy have a valid username or password
                IActionResult Result = Unauthorized();

                //chec to see if the user exist
                if(DoesUserExist(User.Username)){
                    //true
                    //we want to store the user object
                    //to create another helper function
                    UserModel foundUser = GetUserByUsername(User.Username);
                    //Check if the password is correct
                    if(VerifyUserPassword(User.Password, foundUser.Hash, foundUser.Salt)){
                        var secretKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("superSecretKey@345"));
                    var signinCredentials = new SigningCredentials(secretKey, SecurityAlgorithms.HmacSha256);
                    var tokeOptions = new JwtSecurityToken(
                        issuer: "http://localhost:5000",
                        audience: "http://localhost:5000",
                        claims: new List<Claim>(),
                        expires: DateTime.Now.AddMinutes(30),
                        signingCredentials: signinCredentials);
                    var tokenString = new JwtSecurityTokenHandler().WriteToken(tokeOptions);
                    Result = Ok(new { Token = tokenString });
                    }
                }
                return Result;
            }

            public UserModel GetUserByUsername(string? username){
                return _context.UserInfo.SingleOrDefault(user => user.Username == username);
            }

            public bool UpdateUser(UserModel userToUpdate){
                //this one is sending over the whole object to be updated 
                _context.Update<UserModel>(userToUpdate);
                return _context.SaveChanges() != 0;
            }


            public bool UpdateUsername(int id, string username){
                UserModel foundUser = GetUserById(id);
                bool result = false;
                if(foundUser != null){
                    //A user was found
                foundUser.Username = username;
                _context.Update<UserModel>(foundUser);
                result = _context.SaveChanges() != 0;
                }
                return result;
            }
            
            public UserModel GetUserById(int id){
                return _context.UserInfo.SingleOrDefault(user => user.Id == id);
            }

             public bool DeleteUser(string userToDelete){
                //this one is just sending over the username
                //we have to get the object to be deleted
                UserModel foundUser = GetUserByUsername(userToDelete);
                bool result = false;
                if(foundUser != null){
                    //A user was found 
                    _context.Remove<UserModel>(foundUser);
                    result = _context.SaveChanges() != 0;
                }
                return result;
            } 
    }
}

