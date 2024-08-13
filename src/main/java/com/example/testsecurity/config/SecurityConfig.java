package com.example.testsecurity.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
    /**
     * 스프링 시큐리티는 사용자 인증(로그인)시 비밀번호에 대해 단방향 해시 암호화를 진행하여 저장되어 있는 비밀번호와 대조
     * 스프링 시큐리티는 암호화를 위해 BCrypt Password Encoder를 제공하고 권장
     */
    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
     * Role Hierarchy
     * 권한 A, 권한 B, 권한 C가 존재하고 권한의 계층은 “A < B < C”라고 설정을 진행하고 싶은 경우 RoleHierarchy 설정을 진행
     */

    @Bean
    public RoleHierarchy roleHierarchy() {

        RoleHierarchyImpl hierarchy = new RoleHierarchyImpl();

        hierarchy.setHierarchy("ROLE_C > ROLE_B\n" +
                "ROLE_B > ROLE_A");

        return hierarchy;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests((auth) -> auth
                        .requestMatchers("/", "/login", "/loginProc", "join", "/joinProc").permitAll()
                        .requestMatchers("/admin").hasRole("ADMIN")
                        .requestMatchers("/my/**").hasAnyRole("ADMIN", "USER")
                        .anyRequest().authenticated()
                );

//                .authorizeHttpRequests((auth) -> auth
//                        .requestMatchers("/login").permitAll()
//                        .requestMatchers("/").hasAnyRole("A")
//                        .requestMatchers("/manager").hasAnyRole("B")
//                        .requestMatchers("/admin").hasAnyRole("C")
//                        .anyRequest().authenticated()
//                );

        /**
         * CSRF(Cross-Site Request Forgery)는 요청을 위조하여 사용자가 원하지 않아도 서버측으로 특정 요청을 강제로 보내는 방식이다. (회원 정보 변경, 게시글 CRUD를 사용자 모르게 요청)
         * 개발 환경에서는 Security Config 클래스를 통해 csrf 설정을 disable 설정하였다.
         * 배포 환경에서는 csrf 공격 방지를 위해 csrf disable 설정을 제거하고 추가적인 설정을 진행해야 한다.
         */
        http.csrf((auth) -> auth.disable());

        http
                .formLogin((auth) -> auth.loginPage("/login") //로그인 페이지 설정
                        .loginProcessingUrl("/loginProc").permitAll() //프론트에서 넘긴 로그인 데이터를 시큐리티에서 처리
                );
        /**
         * Http Basic 인증 방식
         * 아이디와 비밀번호를 Base64 방식으로 인코딩한 뒤 HTTP 인증 헤더에 부착하여 서버측으로 요청을 보내는 방식
         */
//        http
//                .httpBasic(Customizer.withDefaults());

        /**
         * 다중 로그인 설정
         * maximumSession(정수) : 하나의 아이디에 대한 다중 로그인 허용 개수
         * maxSessionPreventsLogin(불린) : 다중 로그인 개수를 초과하였을 경우 처리 방법
         * true : 초과시 새로운 로그인 차단
         * false : 초과시 기존 세션 하나 삭제
         */
        http
                .sessionManagement((auth) -> auth
                .maximumSessions(1)
                .maxSessionsPreventsLogin(true)
        );

        /**
         * 세션 고정 보호
         * 해커로부터 세션 고정 공격을 보호
         * sessionManagement().sessionFixation().none() : 로그인 시 세션 정보 변경 안함
         * sessionManagement().sessionFixation().newSession() : 로그인 시 세션 새로 생성
         * sessionManagement().sessionFixation().changeSessionId() : 로그인 시 동일한 세션에 대한 id 변경
         */
        http
                .sessionManagement((auth) -> auth
                        .sessionFixation((sessionFixation) -> sessionFixation
                                .changeSessionId())
                );

        /**
         * GET 방식 로그아웃을 진행할 경우 설정 방법
         * csrf 설정시 POST 요청으로 로그아웃을 진행해야 하지만 아래 방식을 통해 GET 방식으로 진행할 수 있다.
         */
        http
                .logout((auth) -> auth.logoutUrl("/logout")
                        .logoutSuccessUrl("/"));

        return http.build();
    }

    /**
     * InMemory 방식 유저 저장
     * 소수의 회원 정보만 가지며 데이터베이스라는 자원을 투자하기 힘든 경우는 회원가입 없는 InMemory 방식으로 유저를 저장
     */
//    @Bean
//    public UserDetailsService userDetailsService() {
//
//        UserDetails user1 = User.builder()
//                .username("user1")
//                .password(bCryptPasswordEncoder().encode("1234"))
//                .roles("ADMIN")
////                .roles("C")
//                .build();
//
//        UserDetails user2 = User.builder()
//                .username("user2")
//                .password(bCryptPasswordEncoder().encode("1234"))
//                .roles("USER")
//                .build();
//
//        return new InMemoryUserDetailsManager(user1, user2);
//    }
}
