package example;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrations;
import org.springframework.security.saml2.provider.service.registration.InMemoryRelyingPartyRegistrationRepository;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .saml2Login()
                .and()
                .authorizeRequests()
                .antMatchers("/sp/test", "/sp/saml/metadata").permitAll() // Allow unauthenticated access
                .anyRequest().authenticated(); // Secure all other requests

        return http.build();
    }

    @Bean
    public InMemoryRelyingPartyRegistrationRepository relyingPartyRegistrationRepository() {
        RelyingPartyRegistration registration = RelyingPartyRegistrations
                .fromMetadataLocation("https://ssologin.cuny.edu/idp/metadata/oam-saml-metadata.xml")
                .registrationId("samlexample")
                .entityId("test-service-provider")
                .assertionConsumerServiceLocation("http://172.27.9.4:8080/sp/login/saml2/sso/samlexample")
                .build();

        return new InMemoryRelyingPartyRegistrationRepository(registration);
    }

}
