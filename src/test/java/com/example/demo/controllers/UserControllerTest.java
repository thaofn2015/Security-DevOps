package com.example.demo.controllers;

import com.example.demo.TestUtils;
import com.example.demo.model.persistence.User;
import com.example.demo.model.persistence.repositories.CartRepository;
import com.example.demo.model.persistence.repositories.UserRepository;
import com.example.demo.model.requests.CreateUserRequest;
import org.junit.Before;
import org.junit.Test;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.util.Optional;

import static org.junit.Assert.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class UserControllerTest {

    private UserController userController;
    private UserRepository userRepository = mock(UserRepository.class);
    private CartRepository cartRepository = mock(CartRepository.class);
    private BCryptPasswordEncoder bCryptPasswordEncoder = mock(BCryptPasswordEncoder.class);
    @Before
    public void setUp() {
        userController = new UserController();
        TestUtils.injectObjects(userController,"userRepository", userRepository);
        TestUtils.injectObjects(userController,"cartRepository", cartRepository);
        TestUtils.injectObjects(userController,"bCryptPasswordEncoder", bCryptPasswordEncoder);
    }
    public CreateUserRequest getCreateUserRequest() {
        CreateUserRequest r = new CreateUserRequest();
        r.setUsername(TestUtils.USER_NAME);
        r.setPassword(TestUtils.PASSWORD);
        r.setConfirmPassword(TestUtils.PASSWORD);
        return r;
    }

    @Test
    public void dCreateUserOk() {
        when(bCryptPasswordEncoder.encode(TestUtils.PASSWORD)).thenReturn("thisIsHashed");

        final ResponseEntity<User> response = userController.createUser(getCreateUserRequest());

        assertNotNull(response);
        assertEquals(200, response.getStatusCodeValue());

        User u = response.getBody();
        assertNotNull(u);
        assertEquals(0, u.getId());
        assertEquals(TestUtils.USER_NAME, u.getUsername());
        assertEquals("thisIsHashed", u.getPassword());
    }

    @Test
    public void createUserfail() {
        // password not match
        CreateUserRequest reqPasswordNotMatch = getCreateUserRequest();
        reqPasswordNotMatch.setConfirmPassword("PasswordNotMatch");
        final ResponseEntity<User> resPasswordNotMatch = userController.createUser(reqPasswordNotMatch);
        assertNotNull(resPasswordNotMatch);
        assertEquals(400, resPasswordNotMatch.getStatusCodeValue());

        // password < 7
        CreateUserRequest reqPassword = getCreateUserRequest();
        reqPassword.setPassword("");
        reqPassword.setConfirmPassword("empty");
        final ResponseEntity<User> resPassword = userController.createUser(reqPassword);
        assertNotNull(resPassword);
        assertEquals(400, resPassword.getStatusCodeValue());
    }

    @Test
    public void findUserOk() {
        User userTest = new User(1L, TestUtils.USER_NAME, TestUtils.PASSWORD);

        // find by id
        when(userRepository.findById(1L)).thenReturn(Optional.of(userTest));
        final ResponseEntity<User> resFindById = userController.findById(userTest.getId());
        User user = resFindById.getBody();
        assertNotNull(user);
        assertEquals(1L, user.getId());
        assertEquals(TestUtils.USER_NAME, user.getUsername());

        // find by name
        when(userRepository.findByUsername(TestUtils.USER_NAME)).thenReturn(userTest);
        final ResponseEntity<User> resFindByName = userController.findByUserName(TestUtils.USER_NAME);
        user = resFindByName.getBody();
        assertNotNull(user);
        assertEquals(1L, user.getId());
        assertEquals(TestUtils.USER_NAME, user.getUsername());
    }

    @Test
    public void findUserfail() {
        // find by id
        final ResponseEntity<User> responseByID = userController.findById(2L);
        assertNull(responseByID.getBody());

        // find by name
        final ResponseEntity<User> responseByName = userController.findByUserName("notAName");
        assertNull(responseByName.getBody());
    }
}