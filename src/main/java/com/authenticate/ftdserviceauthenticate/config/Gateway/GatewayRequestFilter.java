//package com.authenticate.ftdserviceauthenticate.config.Gateway;
//
//import jakarta.servlet.FilterChain;
//import jakarta.servlet.ServletException;
//import jakarta.servlet.http.HttpServletRequest;
//import jakarta.servlet.http.HttpServletResponse;
//import org.slf4j.Logger;
//import org.slf4j.LoggerFactory;
//import org.springframework.security.core.context.SecurityContextHolder;
//import org.springframework.stereotype.Component;
//import org.springframework.web.filter.OncePerRequestFilter;
//import org.springframework.beans.factory.annotation.Value;
//import java.io.IOException;
//
//@Component
//public class GatewayRequestFilter extends OncePerRequestFilter {
//
//    @Value("${app.gateway.header.gateway-secret}")
//    private String gatewaySecretHeader;
//
//    @Value("${app.gateway.secret-key}")
//    private String expectedGatewaySecret;
//
//    @Value("${app.gateway.ip}")
//    private String allowedGatewayIp;
//
//    private static final Logger logger = LoggerFactory.getLogger(GatewayRequestFilter.class);
//
//    @Override
//    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
//        String requestPath = request.getRequestURI();
//
//        // To authorise public authentification endpoints and health check
//        if (requestPath.startsWith("/api/auth/") || requestPath.equals("/actuator/health")) {
//            filterChain.doFilter(request, response);
//            return;
//        }
//
//        // Validate that the request is from the gateway
//        if (!isValidGatewayRequest(request)) {
//            logger.warn("Non autorise request from IP: {}, Path: {}",
//                    getClientIpAddress(request), requestPath);
//            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
//            response.setContentType("application/json");
//            response.getWriter().write("{\"error\":\"Access denied - non autorise request\"}");
//            return;
//        }
//
//        // Simple authentification for gateway request
//        GatewayAuthentication authentication = new GatewayAuthentication();
//        SecurityContextHolder.getContext().setAuthentication(authentication);
//
//        logger.debug("Request validate from the gateway for: {}", requestPath);
//        filterChain.doFilter(request, response);
//
//    }
//
//    private boolean isValidGatewayRequest(HttpServletRequest request) {
//        String clientIp = getClientIpAddress(request);
//
//        logger.debug("Client IP: {}", clientIp);
//        logger.debug("Expected IP: {}", allowedGatewayIp);
//        logger.debug("Gateway secret header: {}", gatewaySecretHeader);
//
//
//        if (!allowedGatewayIp.equals(clientIp) && !"127.0.0.1".equals(allowedGatewayIp)) {
//            logger.warn("IP not autorise: {}, awaited IP {}" ,clientIp, allowedGatewayIp);
//            return false;
//        }
//
//        String gatewaySecret = request.getHeader(gatewaySecretHeader);
//        logger.debug("Gateway secret: {}", gatewaySecret);
//        if (!expectedGatewaySecret.equals(gatewaySecret)) {
//            logger.warn("Invalid gateway secret");
//            return false;
//        }
//
//        return true;
//    }
//
//    private String getClientIpAddress(HttpServletRequest request) {
//        logger.info("=== DEBUG getClientIpAddress ===");
//        logger.info("X-Forwarded-For header: '{}'", request.getHeader("X-Forwarded-For"));
//        logger.info("X-Real-IP header: '{}'", request.getHeader("X-Real-IP"));
//        logger.info("X-Gateway-Secret header: '{}'", request.getHeader("X-Gateway-Secret"));
//        logger.info("Remote address: '{}'", request.getRemoteAddr());
//        String xForwardedFor = request.getHeader("X-Forwarded-For");
//        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
//            return xForwardedFor.split(",")[0].trim();
//        }
//
//        String xRealIp = request.getHeader("X-Real-IP");
//        if (xRealIp != null && !xRealIp.isEmpty()) {
//            return xRealIp;
//        }
//        logger.info("Using remote address: '{}'", request.getRemoteAddr());
//        return request.getRemoteAddr();
//    }
//}
