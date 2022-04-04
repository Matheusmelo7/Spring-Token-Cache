package br.com.alura.forum.config.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import br.com.alura.forum.repository.UsuarioRepository;

@EnableWebSecurity
/*Habilita o security */
@Configuration
/*Defini ao Spring que é uma classe de configuração*/

@Profile(value = {"prod","test"})
public class SecurityConfigurations extends WebSecurityConfigurerAdapter {
											/*Herda da classe acima métodos de configuração */
	@Autowired
	private AutenticacaoService autenticacaoService;
	
	@Autowired
	private TokenService tokenService;
	
	@Autowired
	private UsuarioRepository usuarioRepository;
	
	@Override
	@Bean
	protected AuthenticationManager authenticationManager() throws Exception {
		return super.authenticationManager();
	}
	
	//Configuracoes de autenticacao
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.userDetailsService(autenticacaoService).passwordEncoder(new BCryptPasswordEncoder());
													/*Esse é o metódo de criptografar*/
													/*na senha cadastrada no banco de dados 12345 devolve
													 $2a$10$sFKmbxbG4ryhwPNx/l3pgOJSt.fW1z6YcUnuE2X8APA/Z3NI/oSpq
													 */
	}
	
	//Configuracoes de autorizacao
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.authorizeRequests()
		.antMatchers(HttpMethod.GET, "/topicos").permitAll()
		.antMatchers(HttpMethod.GET, "/topicos/*").permitAll()
				/*Estamos permitindo requisições do tipo GET para o EndPoint GET 1*/

				.antMatchers(HttpMethod.POST, "/auth").permitAll()
				/*Estamos permitindo o Post para enviar o usuário e senha3*/

		.antMatchers(HttpMethod.GET, "/actuator/*").permitAll()
				/*Estamos permitindo o get no endpoint actuator para controle 6*/

		.antMatchers(HttpMethod.DELETE, "/topicos/*").hasRole("MODERADOR")
				/*estamos permitindo que um usuário moderador exclua um topico no caso 4*/

		.anyRequest().authenticated() /*Qualquer outra consulta necessita de autenticação2*/

				.and().csrf().disable()
		.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
		.and().addFilterBefore(new AutenticacaoViaTokenFilter(tokenService, usuarioRepository), UsernamePasswordAuthenticationFilter.class);
			/*Estamos utilizando
			* o stateless para fazer uma requisição */
	}
	
	
	//Configuracoes de recursos estaticos(js, css, imagens, etc.)
	@Override
	public void configure(WebSecurity web) throws Exception {

		web.ignoring()
				.antMatchers("/**.html", "/v2/api-docs", "/webjars/**", "/configuration/**", "/swagger-resources/**");

	}
	
}
