package org.gonzalad.fediz.sample.oidc.config;

import java.util.Arrays;
import java.util.List;

import org.apache.cxf.rs.security.oauth2.common.Client;
import org.gonzalad.cxf.fediz.oidc.config.annotation.web.builders.OidcServerBuilder;
import org.gonzalad.cxf.fediz.oidc.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;

/**
 * @author agonzalez
 */
@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends AuthorizationServerConfigurerAdapter {

    @Override
    public void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .antMatchers("/", "/home").permitAll()
                .anyRequest().authenticated()
                .and()
                .formLogin()
                .loginPage("/login")
                .permitAll()
                .and()
                .logout()
                .permitAll();
    }

    @Override
    public void configure(OidcServerBuilder authorizationServer) throws Exception {
        authorizationServer
                .clientRegistration().clients(clients())
                .and()
                .idp()
                .authorizationCode()
                .scopesRequiringNoConsent("openid", "refreshToken");
    }

    private List<Client> clients() {
        // TODO: an easier builder would be cool (i.e. to forget the call to client.setConfidential if we already
        // have set the value of clientSecret ) -> otherwise it's a bit difficult to debug (i.e. 401 error=unauthorized_client)
        Client client = new Client();
        client.setApplicationName("Sample Application");
        client.setClientId("dsxzJG8rMLJF3A");
        client.setClientSecret("4Kr1wBK3pzN-SBoqOi0dpA");
        client.setRedirectUris(Arrays.asList("http://localhost:9999/login"));
        client.setConfidential(true);
        return Arrays.asList(client);
    }

    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
        auth
                .inMemoryAuthentication()
                .withUser("user").password("password").roles("USER");
    }
}