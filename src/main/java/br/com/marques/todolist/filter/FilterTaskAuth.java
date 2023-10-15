package br.com.marques.todolist.filter;

import java.io.IOException;
import java.util.Base64;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import at.favre.lib.crypto.bcrypt.BCrypt;
import br.com.marques.todolist.user.IUserRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class FilterTaskAuth extends  OncePerRequestFilter{

  @Autowired
  private IUserRepository userRepository;

  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
      throws ServletException, IOException {

        //validando rota
        var servletPath = request.getServletPath();
        if (servletPath.startsWith("/tasks/")){

          //pegar usuario e senha // tratamento de divisao de usauario e senha 
          var authorization = request.getHeader("Authorization");
          var authEncode = authorization.substring("Basic".length()).trim();
          byte[] authDecode = Base64.getDecoder().decode(authEncode);
          
          var authString = new String(authDecode);
          String [] credentials = authString.split(":");
          String username = credentials[0];
          String password = credentials[1];

          //validar usuario 
          var user = this.userRepository.findByUsername(username);
          if (user == null){
            response.sendError(401);

          } else {
            //validar senha
            var passwordVerfiry = BCrypt.verifyer().verify(password.toCharArray(), user.getPassword());
            if (passwordVerfiry.verified){
              //sett Idduser como o valor .getID para "request.setAtt" para o Taskcontroller ter acesso.
              //segue viagem.
              request.setAttribute("IdUser", user.getId());
              filterChain.doFilter(request, response);

            } else {
              response.sendError(401);
            }

          } 

        } else {
          filterChain.doFilter(request, response);
        }   
  }
}
