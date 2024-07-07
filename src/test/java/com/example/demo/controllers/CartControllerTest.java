package com.example.demo.controllers;

import com.example.demo.TestUtils;
import com.example.demo.model.persistence.Cart;
import com.example.demo.model.persistence.Item;
import com.example.demo.model.persistence.User;
import com.example.demo.model.persistence.repositories.CartRepository;
import com.example.demo.model.persistence.repositories.ItemRepository;
import com.example.demo.model.persistence.repositories.UserRepository;
import com.example.demo.model.requests.ModifyCartRequest;
import org.junit.Before;
import org.junit.Test;
import org.springframework.http.ResponseEntity;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Optional;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class CartControllerTest {

    private CartController cartController;
    private UserRepository userRepository = mock(UserRepository.class);
    private CartRepository cartRepository = mock(CartRepository.class);
    private ItemRepository itemRepository = mock(ItemRepository.class);

    @Before
    public void setUp() {
        cartController = new CartController();
        TestUtils.injectObjects(cartController,"userRepository", userRepository);
        TestUtils.injectObjects(cartController,"cartRepository", cartRepository);
        TestUtils.injectObjects(cartController,"itemRepository", itemRepository);
    }

    @Test
    public void addSuccess() {
        Cart cart = new Cart();
        User userTest = new User(1L, TestUtils.USER_NAME, TestUtils.PASSWORD, cart);
        Item item1 = new Item(1L, "Round Widget", BigDecimal.valueOf(2.99), "A widget that is round");

        ModifyCartRequest modifyCartRequest = new ModifyCartRequest();
        modifyCartRequest.setUsername(TestUtils.USER_NAME);
        modifyCartRequest.setItemId(1L);
        modifyCartRequest.setQuantity(2);

        when(userRepository.findByUsername(TestUtils.USER_NAME)).thenReturn(userTest);
        when(itemRepository.findById(1L)).thenReturn(Optional.of(item1));

        ResponseEntity<Cart> responseEntity = cartController.addTocart(modifyCartRequest);
        assertNotNull(responseEntity);
        assertEquals(200, responseEntity.getStatusCodeValue());
        Cart cartAdd = responseEntity.getBody();
        assertEquals(cartAdd.getItems(), Arrays.asList(item1, item1));
    }

    @Test
    public void removeSuccess() {
        Cart cart = new Cart();
        User userTest = new User(1L, TestUtils.USER_NAME, TestUtils.PASSWORD, cart);
        Item item1 = new Item(1L, "Round Widget", BigDecimal.valueOf(2.99), "A widget that is round");

        when(userRepository.findByUsername(TestUtils.USER_NAME)).thenReturn(userTest);
        when(itemRepository.findById(1L)).thenReturn(Optional.of(item1));

        ModifyCartRequest modifyCartRequest = new ModifyCartRequest();
        modifyCartRequest.setUsername(TestUtils.USER_NAME);
        modifyCartRequest.setItemId(1L);
        modifyCartRequest.setQuantity(1);

        ResponseEntity<Cart> responseEntity = cartController.removeFromcart(modifyCartRequest);
        assertNotNull(responseEntity);
        assertEquals(200, responseEntity.getStatusCodeValue());
        Cart cartRemove = responseEntity.getBody();
        assertEquals(cartRemove.getItems(), new ArrayList<>());
    }

    @Test
    public void addFailed() {
        // user missing
        ModifyCartRequest modifyCartRequest = new ModifyCartRequest();
        modifyCartRequest.setUsername(TestUtils.USER_NAME);
        modifyCartRequest.setItemId(1L);
        modifyCartRequest.setQuantity(2);
        when(userRepository.findByUsername(TestUtils.USER_NAME)).thenReturn(null);
        ResponseEntity<Cart> responseUserMissing = cartController.addTocart(modifyCartRequest);
        assertNotNull(responseUserMissing);
        assertEquals(404, responseUserMissing.getStatusCodeValue());

        // item missing
        Cart cart = new Cart();
        User userTest = new User(1L, TestUtils.USER_NAME, TestUtils.PASSWORD, cart);
        when(userRepository.findByUsername(TestUtils.USER_NAME)).thenReturn(userTest);
        when(itemRepository.findById(1L)).thenReturn(Optional.empty());
        ResponseEntity<Cart> responseItemMissing = cartController.addTocart(modifyCartRequest);
        assertNotNull(responseItemMissing);
        assertEquals(404, responseItemMissing.getStatusCodeValue());
    }

    @Test
    public void removeFailed() {
        // user missing
        ModifyCartRequest removeFromCartRequest = new ModifyCartRequest();
        removeFromCartRequest.setUsername(TestUtils.USER_NAME);
        removeFromCartRequest.setItemId(1L);
        removeFromCartRequest.setQuantity(1);
        when(userRepository.findByUsername(TestUtils.USER_NAME)).thenReturn(null);
        ResponseEntity<Cart> responseUserMissing = cartController.removeFromcart(removeFromCartRequest);
        assertNotNull(responseUserMissing);
        assertEquals(404, responseUserMissing.getStatusCodeValue());

        // item missing
        Cart cart = new Cart();
        User userTest = new User(1L, TestUtils.USER_NAME, TestUtils.PASSWORD, cart);
        when(userRepository.findByUsername(TestUtils.USER_NAME)).thenReturn(userTest);
        when(itemRepository.findById(1L)).thenReturn(Optional.empty());
        ResponseEntity<Cart> responseItemMissing = cartController.removeFromcart(removeFromCartRequest);
        assertNotNull(responseItemMissing);
        assertEquals(404, responseItemMissing.getStatusCodeValue());
    }
}