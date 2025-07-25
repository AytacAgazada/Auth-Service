package com.example.authservice.security.jwt;

import com.example.authservice.security.services.UserDetailsServiceImpl;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component; // Bu əlavə olunur
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component // Filteri Spring komponenti kimi qeyd edirik
@Slf4j
@RequiredArgsConstructor // Final sahələr üçün konstruktor yaradır və @Autowired funksiyasını yerinə yetirir
public class AuthTokenFilter extends OncePerRequestFilter {

    // Artıq @Autowired ilə avtomatik inject ediləcək
    private final JwtUtils jwtUtils;
    private final UserDetailsServiceImpl userDetailsService;

    // Default boş konstruktor silinir, çünki @RequiredArgsConstructor hər ikisini idarə edəcək.
    // Əl ilə set edən metodlar (setJwtUtils, setUserDetailsService) və afterPropertiesSet də silinir.

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        try {
            String jwt = parseJwt(request);
            if (jwt != null && jwtUtils.validateJwtToken(jwt)) {
                String fin = jwtUtils.getUserFinFromJwtToken(jwt);

                UserDetails userDetails = userDetailsService.loadUserByUsername(fin);
                UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                        userDetails,
                        null,
                        userDetails.getAuthorities());
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        } catch (Exception e) {
            log.error("Cannot set user authentication: {}", e.getMessage());
        }

        filterChain.doFilter(request, response);
    }

    private String parseJwt(HttpServletRequest request) {
        String headerAuth = request.getHeader("Authorization");

        if (StringUtils.hasText(headerAuth) && headerAuth.startsWith("Bearer ")) {
            return headerAuth.substring(7);
        }
        return null;
    }
}