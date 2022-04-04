package br.com.alura.forum.config.security;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import br.com.alura.forum.modelo.Usuario;
import br.com.alura.forum.repository.UsuarioRepository;

public class AutenticacaoViaTokenFilter extends OncePerRequestFilter {
	
	private TokenService tokenService;
	private UsuarioRepository repository;

	public AutenticacaoViaTokenFilter(TokenService tokenService, UsuarioRepository repository) {
		this.tokenService = tokenService;
		this.repository = repository;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		/*armazena um atributo ja filtrado*/
		String token = recuperarToken(request);
		boolean valido = tokenService.isTokenValido(token);
		/*verifica autenticidade do token no metodo criado por nós isTokenValido*/
		if (valido) {
			autenticarCliente(token);
			/*sendo valido autentica o cliente*/
		}
		
		filterChain.doFilter(request, response);
		/*sendo invalido retorna erro ao solicitante*/
	}

	private void autenticarCliente(String token) {
		Long idUsuario = tokenService.getIdUsuario(token);
		Usuario usuario = repository.findById(idUsuario).get();
		UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(usuario, null, usuario.getAuthorities());
		SecurityContextHolder.getContext().setAuthentication(authentication);
	}

	private String recuperarToken(HttpServletRequest request) {
		/*metodo da classe httpservlerequest retorna o valor do cabecalho
		 para a variavel token*/
		String token = request.getHeader("Authorization");
		/*se o token não existir ou for invalido*/
		if (token == null || token.isEmpty() || !token.startsWith("Bearer ")) {
			return null;
		}
		/*contendo retorno, pula caracteres do tipo e retorna o token no metodo*/
		return token.substring(7, token.length());
	}

}
