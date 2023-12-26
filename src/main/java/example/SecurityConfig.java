package example;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrations;
import org.springframework.security.saml2.provider.service.web.Saml2MetadataFilter;
import org.springframework.security.saml2.provider.service.registration.InMemoryRelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.servlet.filter.Saml2WebSsoAuthenticationFilter;
import org.springframework.security.saml2.provider.service.web.DefaultRelyingPartyRegistrationResolver;
// Other imports


@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .saml2Login()
            .and()
            .addFilterBefore(saml2MetadataFilter(), Saml2WebSsoAuthenticationFilter.class)
            .authorizeRequests()
            .antMatchers("/**").authenticated();
    }

    @Bean
    public RelyingPartyRegistrationRepository relyingPartyRegistrationRepository() {
        RelyingPartyRegistration registration = RelyingPartyRegistrations
            .fromMetadataLocation("https://ssologin.cuny.edu/idp/metadata/oam-saml-metadata.xml")
            .registrationId("samlexample")
            .entityId("test-service-provider") // "http://172.27.9.4:8080/sp/login/saml2/sso/samlexample"
            .assertionConsumerServiceUrlTemplate("https://172.27.9.4:8080/sp/login/saml2/sso/{registrationId}")
            .build();

        return new InMemoryRelyingPartyRegistrationRepository(registration);
    }

    @Bean
    public Saml2MetadataFilter saml2MetadataFilter() {
    return new org.springframework.security.saml2.provider.service.web.Saml2MetadataFilter(
            new DefaultRelyingPartyRegistrationResolver(relyingPartyRegistrationRepository()),
            null  // No need to explicitly provide a metadata resolver
    	);
    }
}
