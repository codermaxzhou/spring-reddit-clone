package com.example.demo.exceptions;

import com.example.demo.dto.PostRequest;

public class SubredditNotFoundException extends RuntimeException {
    public SubredditNotFoundException(String message) {
        super(message);
    }
}
