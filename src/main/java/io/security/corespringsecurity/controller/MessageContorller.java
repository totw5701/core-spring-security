package io.security.corespringsecurity.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
public class MessageContorller {

    @GetMapping(value="/messages")
    public String mypage() throws Exception {
        return "user/messages";
    }

    @GetMapping("/api/messages")
    @ResponseBody
    public String apiMessage() {
        return "messages ok";
    }
}
