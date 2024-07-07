package com.example.demo.controllers;

import com.example.demo.TestUtils;
import com.example.demo.model.persistence.Cart;
import com.example.demo.model.persistence.Item;
import com.example.demo.model.persistence.User;
import com.example.demo.model.persistence.UserOrder;
import com.example.demo.model.persistence.repositories.OrderRepository;
import com.example.demo.model.persistence.repositories.UserRepository;
import org.junit.Before;
import org.junit.Test;
import org.springframework.http.ResponseEntity;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class OrderControllerTest {

    private OrderController orderController;
    private UserRepository userRepository = mock(UserRepository.class);
    private OrderRepository orderRepository = mock(OrderRepository.class);

    @Before
    public void setUp(){
        orderController = new OrderController();
        TestUtils.injectObjects(orderController,"userRepository", userRepository);
        TestUtils.injectObjects(orderController,"orderRepository", orderRepository);
    }

    @Test
    public void submitSuccess() {
        Cart cart = new Cart();
        User userTest = new User(1L, TestUtils.USER_NAME, TestUtils.PASSWORD, cart);
        List<Item> items = new ArrayList<>();
        BigDecimal total = new BigDecimal(0);

        Item item1 = new Item(1L, "Round Widget", BigDecimal.valueOf(2.99), "A widget that is round");
        Item item2 = new Item(2L, "Square Widget", BigDecimal.valueOf(1.99), "A widget that is square");
        items.add(item1);
        items.add(item2);
        total.add(item1.getPrice());
        total.add(item2.getPrice());

        cart.setItems(items);
        cart.setTotal(total);
        cart.setUser(userTest);

        when(userRepository.findByUsername(TestUtils.USER_NAME)).thenReturn(userTest);
        ResponseEntity<UserOrder> responseEntity = orderController.submit(TestUtils.USER_NAME);
        assertNotNull(responseEntity);
        assertEquals(200, responseEntity.getStatusCodeValue());
        UserOrder userOrder = responseEntity.getBody();
        assertEquals(userOrder.getItems(), items);
        assertEquals(userOrder.getUser().getUsername(), userTest.getUsername());
        assertEquals(userOrder.getTotal(), total);
    }

    @Test
    public void submitFailed() {
        when(userRepository.findByUsername(TestUtils.USER_NAME)).thenReturn(null);
        ResponseEntity<UserOrder> responseEntity = orderController.submit(TestUtils.USER_NAME);
        assertNotNull(responseEntity);
        assertEquals(404,responseEntity.getStatusCodeValue());
    }

    @Test
    public void getOrdersForUserSuccess() {
        Cart cart = new Cart();
        User userTest = new User(1L, TestUtils.USER_NAME, TestUtils.PASSWORD, cart);
        List<Item> items = new ArrayList<>();
        BigDecimal total = new BigDecimal(0);

        Item item1 = new Item(1L, "Round Widget", BigDecimal.valueOf(2.99), "A widget that is round");
        Item item2 = new Item(2L, "Square Widget", BigDecimal.valueOf(1.99), "A widget that is square");
        items.add(item1);
        items.add(item2);
        total.add(item1.getPrice());
        total.add(item2.getPrice());

        cart.setItems(items);
        cart.setTotal(total);
        cart.setUser(userTest);

        UserOrder userOrder = UserOrder.createFromCart(cart);
        List<UserOrder> userOrderList = Arrays.asList(userOrder);

        when(userRepository.findByUsername(TestUtils.USER_NAME)).thenReturn(userTest);
        when(orderRepository.findByUser(userTest)).thenReturn(userOrderList);
        ResponseEntity<List<UserOrder>> response = orderController.getOrdersForUser(TestUtils.USER_NAME);
        assertNotNull(response);
        assertEquals(200, response.getStatusCodeValue());
        List<UserOrder> userOrderListResponse = response.getBody();
        assertEquals(userOrderListResponse.size(), 1);
        UserOrder userOrderResponse = userOrderListResponse.get(0);
        assertEquals(userOrderResponse.getItems(), items);
        assertEquals(userOrderResponse.getUser().getUsername(), userTest.getUsername());
        assertEquals(userOrderResponse.getTotal(), total);
    }

    @Test
    public void getOrdersForUserfailed() {
        when(userRepository.findByUsername(TestUtils.USER_NAME)).thenReturn(null);
        ResponseEntity<List<UserOrder>> response = orderController.getOrdersForUser(TestUtils.USER_NAME);
        assertNotNull(response);
        assertEquals(404,response.getStatusCodeValue());
    }
}