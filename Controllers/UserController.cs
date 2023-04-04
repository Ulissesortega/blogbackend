using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using blogbackend.Models;
using blogbackend.Models.DTO;
using blogbackend.Services;
using Microsoft.AspNetCore.Mvc;

namespace blogbackend.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class UserController : ControllerBase
    {

        private readonly UserService _data;
        public UserController(UserService dataFromService)
        {
            _data = dataFromService;
        }
        //Login Endpoint
        [HttpPost]
        [Route("Login")]
        public IActionResult Login([FromBody]LoginDTO User)
        {
            return _data.Login(User);
        }


        //Add User
            
            [HttpPost]
            [Route("AddUser")]

            public bool AddUser(CreateAccountDTO UserToAdd)
            {
                return _data.AddUser(UserToAdd);
            }


        //Update User Account
        [HttpPost]
        [Route("UpdateUser")]
        public bool UpdateUser(UserModel userToUpdate){
            return _data.UpdateUser(userToUpdate);
        }
        
        [HttpPost]
        [Route("UpdateUser/{id}/{username}")]
        public bool UpdateUser(int id, string username){
            return _data.UpdateUsername(id, username);
        }


        //Delete User Account
        [HttpDelete]
        [Route("DeleteUser/{userToDelete}")]
        public bool DeleteUser(string userToDelete){
            return _data.DeleteUser(userToDelete);
        } 

    }
}

