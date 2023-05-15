package io.security.corespringsecurity.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class MessageContorller {

    @GetMapping(value="/messages")
    public String mypage() throws Exception {

        return "user/messages";
    }
}
