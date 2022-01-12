package com.example.jwt.config.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.example.jwt.config.auth.PrincipalDetails;
import com.example.jwt.model.User;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;

//스프링 시큐리티에서 UsernamePasswordAuthenticationFilter 가 있음.
//   /login요청해서 username,password 전송하면 (post)
// UsernamePasswordAuthenticationFilter 동작을함
@RequiredArgsConstructor
@Data
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;
//    public JwtAuthenticationFilter() {
//
//    }


    //로그인 요청을 하면 로그인 시도를 위해서 실행되는 함수
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        System.out.println("JwtAuthenticationFilter : 로그인 시도중 ");
        /*
            1. username, password 받아서
            2., 정상인지 로그인 시도를 해본다.  authenticationManager로 로그인 시도를 하면 PrincipalDetailsService가 호출 loadUserByUsername()가 실행됨
            3. PrincipalDetails를 세션에 담고 (권한관리를위해서 )
            4.  JWT만들어서 응답해주면 됨
         */

            try {
                ObjectMapper om = new ObjectMapper();
                User user = om.readValue(request.getInputStream(), User.class);
                System.out.println(user);

                UsernamePasswordAuthenticationToken authenticationToken =
                        new UsernamePasswordAuthenticationToken(user.getPassword(), user.getPassword());
                // principalDetailsService 의 loadUserByUsername() 함수가 실행됨
                // PrincipalDetailsService 의 loadUserByUsernbame() 함수가 실행된 후 정상이면 authentication이 리턴됨.
                Authentication authentication = authenticationManager.authenticate(authenticationToken);

                //authentication 객체가 session 영역에 저장됨. => 로그인이 되었다는 뜻.
                PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
                System.out.println(principalDetails.getUser().getUsername()); // 로그인 정상적으로 되었다는뜻

                //authentication 객체가 session 영역에 저장을 해야하고 그 방법이 return 해주면 됨
                //리턴의 이유는 권한 처리를 security가 대신 해주기 때문에 편하려고 하는거임
                // 굳이 jwt 토큰을 사용하면서 세션을 만들이유가없음 단지 권한처리 떄문에 session 에 넣어주는것

                return authentication;

            } catch (IOException e) {
                e.printStackTrace();
            }

        return null;
    }

    //attempAuthentication 실행후 인증이 정상적으로 되었으면 successfulAuthentication 함수가 실행
    // JWT 토큰을 만들어서 request 요청한 사용자에게 JWT 토큰을 response 해주면됨

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        System.out.println("successfulAuthencation 실행됨: 인증이 완료되었다는 뜻임 ");
        PrincipalDetails principalDetails = (PrincipalDetails) authResult.getPrincipal();
        //RSA방식이 아니라 Hash 암호방식
        String jwtToken = JWT.create()
                .withSubject(principalDetails.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis()+(60000* 10)))
                .withClaim("id", principalDetails.getUser().getId())
                .withClaim("username", principalDetails.getUser().getUsername())
                .sign(Algorithm.HMAC512("cos"));
        response.addHeader("Authorization", "Bearer " + jwtToken);
    }
}
