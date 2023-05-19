package io.security.corespringsecurity.security.token;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

public class AjaxAuthenticationToken extends UsernamePasswordAuthenticationToken {

    /**
     * 토큰 구현이 복잡하니 그냥 UsernamePasswordAuthenticationToken을 그대로 사용하자.
     */
    public AjaxAuthenticationToken(Object principal, Object credentials) {
        super(principal, credentials);
    }

    public AjaxAuthenticationToken(Object principal, Object credentials, Collection<? extends GrantedAuthority> authorities) {
        super(principal, credentials, authorities);
    }
}
