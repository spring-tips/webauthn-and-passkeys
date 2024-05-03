package bootiful.passkeys;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.WebauthnConfigurer;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.web.servlet.function.RouterFunction;
import org.springframework.web.servlet.function.ServerResponse;

import java.util.Map;

import static org.springframework.web.servlet.function.RouterFunctions.route;

@SpringBootApplication
public class PasskeysApplication {


    public static void main(String[] args) {
        SpringApplication.run(PasskeysApplication.class, args);
    }

    @Bean
    PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories
                .createDelegatingPasswordEncoder();
    }

    @Bean
    UserDetailsService userDetailsService(PasswordEncoder passwordEncoder) {
        var user = User
                .withUsername("jlong")
                .password(passwordEncoder.encode("pw"))
                .roles("USER")
                .build();
        return new InMemoryUserDetailsManager(user);
    }

    @Bean
    RouterFunction<ServerResponse> httpEndpoints() {
        return route()
                .GET("/hello", request -> {
                    var user = SecurityContextHolder
                            .getContextHolderStrategy()
                            .getContext()
                            .getAuthentication()
                            .getName();
                    return ServerResponse
                            .ok()
                            .body(Map.of("message", "Hello, " + user + "!"));
                })
                .build();
    }

    @Bean
    DefaultSecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
                .authorizeHttpRequests(a -> a
                        .requestMatchers("/login/**").permitAll()
                        .anyRequest().authenticated())
                .with(new WebauthnConfigurer<>(), passkeys -> passkeys
                        .rpId("localhost")
                        .rpName("Bootiful Passkeys")
                        .allowedOrigins("http://localhost:8080")
                )
                .formLogin(Customizer.withDefaults())
                .build();
    }
}
