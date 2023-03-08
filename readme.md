#     微信第三方平台小程序开发思路

  个人对于微信第三方平台小程序的理解以及搭建一个微信小程序及云端服务的一些个人经验，作为交流。

首先，一个第三方平台小程序要定位是面向什么行业，不同的行业顶层设计差别很大。

我的这个第三方平台小程序是面向第三方商家提供的在线下单服务。如：鲜花实体门店的在线下单购买及短距离配配送、餐饮的扫码点餐、小型工厂的自营商城等、有在线下单支付需求的连锁店等。

定位好产品业务范围后，接下来需要整体规划架构设计。架构设计好比是一座大厦的地基部分，设计不好不利于业务的开展。

第二步： 架构设计部分，我简单作个介绍。我会着重从网关、鉴权体系、高可用、高并发设计几个方面展开。



# 1 架构设计

架构设计由SLB、网关、注册/配置中心、微信、基础设施几部分组成。

![<https://coding-2020.s3.cn-northwest-1.amazonaws.com.cn/assets/01.png>](<https://coding-2020.s3.cn-northwest-1.amazonaws.com.cn/assets/01.png>)



其中：SLB： 可购买SLB弹性负载均衡服务，也可以自建，具体就是安装NGINX服务，将域名的后端流量转发至网关。 在此，将NGINX配置文件nginx.conf 贴出来，供参考：



```
user  root;
worker_processes  1;

error_log  /var/logs/nginx/error.log  info;

pid  /var/pids/nginx.pid;


events {
    use epoll;
    worker_connections  1024;
}


http {
    client_header_buffer_size 32k;
    large_client_header_buffers 4 32k;
    fastcgi_buffers 8 16k;
    fastcgi_buffer_size 32k;
    include       mime.types;
    default_type  application/octet-stream;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;

    proxy_set_header X-Forwarded-Proto $scheme;

    proxy_set_header Upgrade $http_upgrade;

    add_header Content-Security-Policy "upgrade-insecure-requests";

    sendfile  on;

    keepalive_timeout  65;
    keepalive_requests 150;
    ssl_certificate      /usr/home/softwares/cer/nginx.crt;
    ssl_certificate_key  /usr/home/softwares/cer/nginx.key;
    gzip on;
    gzip_min_length 1k;
    gzip_buffers 16 64k;
    gzip_http_version 1.1;
    gzip_comp_level 6;
    gzip_types text/plain application/x-javascript text/css application/xml image/jpeg image/gif image/png;
    gzip_vary on;

    upstream back {
      #sticky;
     
      server  127.0.0.1:9091 weight=1 max_fails=1 fail_timeout=6s;
      server  127.0.0.1:9092 weight=1 max_fails=1 fail_timeout=6s;

    }


    # HTTPS server

    server {
        listen       443 ssl;
        listen 80;
        #listen 443 default ssl;
        server_name   XXXX.com;
        ssl_certificate      /usr/home/softwares/cer/nginx.crt;
        ssl_certificate_key  /usr/home/softwares/cer/nginx.key;

        ssl_session_cache    shared:SSL:1m;
        ssl_session_timeout  5m;

        ssl_ciphers  HIGH:!aNULL:!MD5;
        ssl_prefer_server_ciphers  on;

        error_page 502 503 /50x.html;
        if ($scheme = http) {
          return 301 https://$host$request_uri;
         }
    location = /50x.html {
       root /usr/home/softwares/html;
    }
      # 请求不带任何参数，重定向至 https://XXXX.com/home 
      location = / {
        return 301 https://XXXX.com/home;

       }
       location / {
         add_header 'Access-Control-Allow-Origin' 'http://localhost:8080';
         add_header 'Access-Control-Allow-Methods' '*';
         add_header  'Access-Control-Allow-Credentials' 'true';     
         add_header 'Access-Control-Allow-Headers' 'access-control-allow-origin, authority, content-type, version-info, X-Requested-With, Authorization, h5token, token, admintoken,authen';

         if ($request_method = 'OPTIONS') {
            return 204;
         }
          proxy_connect_timeout 6000;
          proxy_set_header Host                         $host:$server_port;
          proxy_set_header X-Forwarded-For     $proxy_add_x_forwarded_for;
          proxy_set_header X-Forwarded-Proto  $scheme;
          proxy_set_header X-Forwarded-Port    $server_port;
          client_max_body_size 10m;
          #limit_reqzone=allips burst=5 nodelay;
          proxy_pass http://back;
          proxy_redirect http:// https://;
          #root /usr/home/softwares/html/home;
          #index index.html;

        }
        location /home {
           root  /usr/home/softwares/html;
           index index.html;

       }

       location /manage {
          root /usr/home/softwares/html;
          index index.html;
       }

       location /much {
          root /usr/home/softwares/html;
          index index.html;
       }

      location /cloud {
          root /usr/home/softwares/html;
          index index.html;
       }

       

         


         location /bc/KNAxhMmH3y.txt {
                  alias    /usr/home/softwares/html/bc/KNAxhMmH3y.txt;
        }
        location ~^.+\.txt$ {
           root /usr/home/softwares/html;
        }
        location /wechat/WXPAY_verify_1600698318.txt {
           alias  /usr/home/softwares/html/wechat/WXPAY_verify_1600698318.txt;
       }

        location /static/images/favicon.ico  {
             alias /usr/home/softwares/html/static/images/favicon.ico;


        }
       location /images/ {
          alias /usr/home/softwares/html/static/images/;
            
        }
     
         location /css/ {
          alias /usr/home/softwares/html/static/css/;
            
        }
        location /js/ {

          alias /usr/home/softwares/html/static/js/;
            
        }

        #gaode map
       # 自定义地图服务代理
        location /_AMapService/v4/map/styles {
            set $args "$args&jscode=高德Key";
            proxy_pass https://webapi.amap.com/v4/map/styles;
        }
        # 海外地图服务代理
        location /_AMapService/v3/vectormap {
            set $args "$args&jscode=高德Key";
            proxy_pass https://fmap01.amap.com/v3/vectormap;
        }
        # Web服务API 代理
        location /_AMapService/ {
            set $args "$args&jscode=高德Key";
            proxy_pass https://restapi.amap.com/;
        }

    }


}


```

其中，9091、9092为网关服务， 与这台NGINX部署在同一台机器。



## 1.1 网关



网关使用spring-cloud-gateway ， 与传统网关不同的是，spring-cloud-gateway 结合了 spring-security ， 对所有的非白名单入网流量进行安全验证，鉴权的原理稍后介绍。 先看 核心的maven 依赖。 服务注册和服务发现使用了nacos。 注意各版本依赖。我使用的 nacos版本是 2.1.2， 故对应的客户端版本是2.1.2。 版本不妆容将会导致各种各样的问题。以下是版本的对照关系。



| 依赖                                       | 版本            | 说明   |
| ---------------------------------------- | ------------- | ---- |
| nacos                                    | 2.2.6.RELEASE |      |
| nacos-client                             | 2.1.2         |      |
| spring-boot                              | 2.3.2.RELEASE |      |
| spring-cloud                             | Hoxton.SR9    |      |
| spring-cloud-alibaba-dependencies        | 2.2.6.RELEASE |      |
| spring-cloud-starter-alibaba-nacos-config | 2.2.6.RELEASE |      |
| spring-cloud-starter-loadbalancer        | 2.2.6.RELEASE |      |

以下是 pom.xml 

### 1.1.1 pom.xml 

```
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 https://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>
      <parent>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-parent</artifactId>
         <version>2.3.2.RELEASE</version>
        <relativePath/> <!-- lookup parent from repository -->

    </parent>
   
    <groupId>com.dian.coding</groupId>
    <artifactId>dian-gateway</artifactId>
    <version>0.0.1-SNAPSHOT</version>
    <name>dian-gateway</name>
    <description>dian-gateway</description>

    <properties>
        <java.version>8</java.version>
        <redis.client.version>2.9.0</redis.client.version>
       <spring.data.redis.version>2.0.8.RELEASE</spring.data.redis.version>
        <reactor.version>3.1.8.RELEASE</reactor.version>
        <feign.version>9.5.1</feign.version>
        <slf4j.version>1.7.25</slf4j.version>

        <!-- nacos -->
        <nacos.version>2.2.6.RELEASE</nacos.version>
        <spring.cloud.version>Hoxton.SR9</spring.cloud.version>
        <spring.boot.version>2.3.2.RELEASE</spring.boot.version>
        <nacos.client.version>2.1.2</nacos.client.version>
        <spring.cloud.alibaba.version>2.2.9.RELEASE</spring.cloud.alibaba.version>


    </properties>


    <dependencies>


        <dependency>
            <groupId>com.dian.coding.sdk</groupId>
            <artifactId>dian-aes-sdk-bi</artifactId>
            <version>1.1</version>
        </dependency>


        <dependency>
            <groupId>com.alibaba.nacos</groupId>
            <artifactId>nacos-client</artifactId>
            <version>2.1.2</version>
        </dependency>


        <dependency>
        <groupId>org.json.web</groupId>
        <artifactId>dian-jwt-encrypt</artifactId>
        <version>1.0</version>
        </dependency>

        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter</artifactId>
        </dependency>


        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-validation</artifactId>
        </dependency>

        
     


      <dependency>
          <groupId>org.springframework.cloud</groupId>
          <artifactId>spring-cloud-starter-gateway</artifactId>

         </dependency>



    
        <dependency>
            <groupId>org.springframework.cloud</groupId>
            <artifactId>spring-cloud-starter-security</artifactId>

        </dependency>



        <!-- fegin -->

        <!--fegin组件-->



        <!-- Feign Client for loadBalancing -->

        <dependency>
            <groupId>org.springframework.cloud</groupId>
            <artifactId>spring-cloud-starter-loadbalancer</artifactId>
        <exclusions>
            <exclusion>
                <artifactId>spring-cloud-starter</artifactId>
                <groupId>org.springframework.cloud</groupId>
            </exclusion>
        </exclusions>


        </dependency>


   <!--  end of spring-cloud-gateway -->
     
    
        <dependency>
        <groupId>io.github.openfeign</groupId>
        <artifactId>feign-okhttp</artifactId>
        </dependency>
    

        <dependency>
            <groupId>org.projectlombok</groupId>
            <artifactId>lombok</artifactId>
            <optional>true</optional>
        </dependency>



        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-actuator</artifactId>
        </dependency>

        <!-- start of  nacos  -->
        <dependency>
            <groupId>com.alibaba.cloud</groupId>
            <artifactId>spring-cloud-starter-alibaba-nacos-discovery</artifactId>

            <exclusions>
                <exclusion>
                    <groupId>com.alibaba.nacos</groupId>
                    <artifactId>nacos-client</artifactId>
                </exclusion>

                <exclusion>
                    <groupId>org.springframework.cloud</groupId>
                    <artifactId>spring-cloud-starter-netflix-ribbon</artifactId>
                </exclusion>




            </exclusions>



        </dependency>

        <!-- 保障配置文件能够动态更新 -->

        <dependency>
            <groupId>com.alibaba.cloud</groupId>
            <artifactId>spring-cloud-starter-alibaba-nacos-config</artifactId>
        </dependency>



        <!-- end of  nacos  -->
     

<dependency>
    <groupId>org.slf4j</groupId>
    <artifactId>slf4j-api</artifactId>
    <version>1.7.30</version>
</dependency>
    <dependency>
    <groupId>org.slf4j</groupId>
    <artifactId>slf4j-log4j12</artifactId>
    <version>1.7.30</version>
</dependency>



        <dependency>
            <groupId>javax.xml.bind</groupId>
            <artifactId>jaxb-api</artifactId>
            <version>2.3.0</version>
        </dependency>
        <dependency>
            <groupId>com.sun.xml.bind</groupId>
            <artifactId>jaxb-impl</artifactId>
            <version>2.3.0</version>
        </dependency>
        <dependency>
            <groupId>com.sun.xml.bind</groupId>
            <artifactId>jaxb-core</artifactId>
            <version>2.3.0</version>
        </dependency>


        <dependency>
            <groupId>com.alibaba.cloud</groupId>
            <artifactId>spring-cloud-alibaba-dependencies</artifactId>

            <type>pom</type>
            <scope>import</scope>
            <version>${spring.cloud.alibaba.version}</version>

        </dependency>




    </dependencies>


    <dependencyManagement>
        <dependencies>



            <dependency>
                <groupId>com.alibaba.cloud</groupId>
                <artifactId>spring-cloud-alibaba-dependencies</artifactId>
                <version>${nacos.version}</version>
                <type>pom</type>
                <scope>import</scope>
            </dependency>




            <dependency>
                <groupId>org.springframework.cloud</groupId>
                <artifactId>spring-cloud-dependencies</artifactId>

                <version>${spring.cloud.version}</version>

                <type>pom</type>
                <scope>import</scope>
            </dependency>


        </dependencies>
    </dependencyManagement>
    

    <build>
      <finalName>dian-gateway</finalName>
        <plugins>
            <plugin>
                <groupId>org.springframework.boot</groupId>
                <artifactId>spring-boot-maven-plugin</artifactId>
            </plugin>
        </plugins>
    </build>

</project>

```



使用 sl4j 作为日志组件。



### 1.1.2 bootstrap.yaml



说明：

（1） 使用 network-interface: eth0 而不显示指定IP，可以减少云主机IP变动未同步修改配置文件IP的风险。

（2） springCloud中需要禁用ribbon。

cloud:
    loadbalancer:
      ribbon:
        enabled: false



```
nacos:
   ip: XX
spring:
  application:
     name: dian-gateway
  profile:
    active: prod
  cloud:
    loadbalancer:
      ribbon:
        enabled: false 
    inetutils:
      preferred-networks: ${nacos.ip}
    bootstrap:
      enabled: true
      log-enable: true
    nacos:
      config:
        refresh:
          enabled: true
        ext-config[0]:
          data-id: ${spring.application.name}-${spring.profile.active}.yaml
          group: ${spring.profile.active}
          refresh: true
        server-addr: ${nacos.ip}:8848
        file-extension: yaml
        contextPath: /nacos
        namespace: 3ca2f55d-060b-4eee-ade7-cfb91976b6bd
        group: ${spring.profile.active}
        username: nacos-client
        password: nacos-client@#1031 
      refresh-enabled: true
      auto-refresh: true
      username: client
      password: nacos-client@#1031
      group: ${spring.profile.active}
      data-id: ${spring.application.name}-${spring.profile.active}.yaml
      namespace: 3ca2f55d-060b-4eee-ade7-cfb91976b6bd
      discovery:
        metadata:
          preserved.heart.beat.interval: 3 #心跳间隔。时间单位:秒。心跳间隔
          preserved.heart.beat.timeout: 6 #心跳暂停。时间单位:秒。 即服务端6秒收不到客户端心跳，会将该客户端注册的实例设为不健康：
          preserved.ip.delete.timeout: 9 #Ip删除超时。时间单位:秒。即服务端9秒收不到客户端心跳，会将该客户端注册的实例删除：
        enable: true
        username: nacosUserName
        password: nacosePassword
        server-addr: ${nacos.ip}:8848
        contextPath: /nacos
        service: ${spring.application.name}
        namespace: 4ca2f00d-060b-4eee-ade7-cf781976b690
        group: ${spring.profile.active}
        secure: false
        network-interface: eth0
        accessKey: accessKey
        secretKey: accessSecurty

management:
  endpoints:
    web:
      exposure:
        include: '*'

```





### 1.1.4 application.yaml



说明： 使用es256 JWT实现加解密。

通过 spring.cloud.gateway.routes 配置微服务的路由。 参考如下：



```
whiteList: /v1/user/token # 白名单
server:
  port: 9091

es256:
  privateKeyPath: /home/ES256/es256-private-key.pem
  publicKey: |
    -----BEGIN PUBLIC KEY-----
    MFkwEwYHKoZIzj0CAQYIKoZIzj78wPuq4RGhqa9woLE/0uiOaqpL
    VJEGEJ7DybT70afBTSp0y5qAKx+Lr4KMX1Mlb+/FkdsGcvYqoWw==
    -----END PUBLIC KEY-----

spring:
  application:
    name: dian-gateway
  cloud:
    loadbalancer:
      ribbon:
        enabled: false

    gateway:
     
      discovery:
        locator:
          enabled: true
      routes:
        - id: dian-merchandise
          uri: lb://dian-merchandise
          predicates:
            - Path=/api/mer/**
          filters:
            - StripPrefix=0
        - id: dian-order
          uri: lb://dian-order
          predicates:
            - Path=/api/order/*    
               省略其他。。。

```





### 1.1.5 网关过滤器 

网关过滤器处理请求，实现转发、限流、鉴权等功能。 SecurityWefluxConfig.java 使用 spring-security来实现RBAC控制。



```
package com.smart.rest.config.security.webflux;

import com.alibaba.fastjson.JSONObject;
import com.dian.coding.sdk.AesUtil;
import io.netty.util.CharsetUtil;
import lombok.extern.log4j.Log4j2;
import org.json.web.jwt.JwtUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authorization.ServerAccessDeniedHandler;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 *  spring-security 核心配置模块
 */

@Log4j2
@Configuration
@EnableWebFluxSecurity
public class SecurityWefluxConfig {
    
   @Autowired
   private MySecurityAuthenManager mySecurityAuthenManager;
   
     @Value("${whiteList}")
     private String whiteList;
     @Autowired
     private AesUtil aesUtil ;
     @Autowired
     private JwtUtils jwtUtils;
     @Autowired
     SecurityContextRepository  securityContextRepository;
   
     @Autowired
     private AuthenSuccessHandler authenSuccessHandler;
   
     @Autowired
     private  AuthenFailHandler authenFailHander;
     
     @Autowired
     private LogoutHandler logoutHandler;
     
     @Autowired
     private UnauthenEntrypoint unauthenEntrypoint;



   @Bean
      public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {


      SecurityWebFilterChain chain =
            http.cors().and().csrf().disable()
                 //http
                  //.csrf().disable()
                  //.cors().disable()
                     .authenticationManager(mySecurityAuthenManager)
                     .securityContextRepository(securityContextRepository).addFilterBefore(new GatewayFilter(aesUtil, jwtUtils),SecurityWebFiltersOrder.CORS)
                     .authorizeExchange()

                     .pathMatchers(" "/api/admin_spring_security_login","/api/open/account/get", "/superadmin/gen/barcode").permitAll()
                     .pathMatchers("/adm/changepwd").hasAnyAuthority("MUCH_ADMIN","SUPER_ADMIN","ADMIN_EDIT","STAFF_EDIT")
                     .pathMatchers("/adm/superadmin/**").hasAnyAuthority("SUPER_ADMIN")
                     .pathMatchers("/much/**").hasAnyAuthority("MUCH_ADMIN","SUPER_ADMIN")
                     
                     .pathMatchers("/staff/**").hasAnyAuthority("STAFF_EDIT")


                   .and().exceptionHandling().authenticationEntryPoint(unauthenEntrypoint)  //未登录访问资源时的处理类，若无此处理类，前端页面会弹出登录
                     .accessDeniedHandler(new ServerAccessDeniedHandler() {
                        @Override
                        public Mono<Void> handle(ServerWebExchange serverWebExchange, AccessDeniedException e) {

                           JSONObject res = new JSONObject();
                           res.fluentPut("resCode", "403").fluentPut("resMsg", "敏感资源拒绝访问");
                           ServerHttpResponse response = serverWebExchange.getResponse();
                           response.getHeaders().set(HttpHeaders.CONTENT_TYPE, "application/json; charset=UTF-8");

                           String result = JSONObject.toJSONString(res);
                           DataBuffer buffer = response.bufferFactory().wrap(result.getBytes(CharsetUtil.UTF_8));
                           return response.writeWith(Mono.just(buffer));

                        }
                     })
                    .and().build();

        
             return chain;
      }
     
     

   
   

}

```



spring-security 仅一张表 admin_roles ( 后台帐号与角色关联表）实现了后台帐号与角色、权限的关系。 表参考如下： 



![https://coding-2020.s3.cn-northwest-1.amazonaws.com.cn/assets/02.png](https://coding-2020.s3.cn-northwest-1.amazonaws.com.cn/assets/02.png)





### 1.1.6 网关鉴权的逻辑

首先，云端后台帐号登录成功时，返回的JSON结果字段中指定roles字段保存角色名称集合，使用平台es256公钥 JWT 加密返回的JSON结果记为token ，H5将此返回 token在每次HTTP请求时均带上头部token， 网关读取token 再用平台私钥对token JWT 解密。 

先看网关过滤器逻辑：

 值得注意的是nacos负载均衡转发HTTP协议默认的是HTTPS，需要转成HTP协议。

 网关主要是对HTTP使用JWT解析头部token，获取roles 集合，再将解析对象转JSON后转发HTTP头部给下游微服务。 不需要下游微服务再执行JWT解析头部token。一是：下游微服务是没有平台私钥，降低私钥泄密的风险；二是：由网关层JWT解析加密token并完成鉴权，不需要微服务二次解析token，提高了系统性能。由于RSA公私钥加解密是有性能损耗的。以下是网关的鉴权逻辑：



```
package com.smart.rest.config.security.webflux;

import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import com.coding.dian.sdk.StackTool;
import com.coding.dian.sdk.constants.ResEnum;
import com.coding.dian.sdk.constants.TokenEnum;
import com.dian.coding.sdk.AesUtil;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.json.web.jwt.JwtUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.Ordered;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.net.URI;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;


@Slf4j

public class GatewayFilter implements WebFilter, Ordered {

    private AesUtil aesUtil;
    private JwtUtils jwtUtils;

    public GatewayFilter(AesUtil aesUtil, JwtUtils jwtUtils) {

        this.aesUtil = aesUtil;
        this.jwtUtils = jwtUtils;

    }

    private static String CODE_OP_FAIL = "1";
    private static String CODE_TOKEN_EXPIRED = "4031021";
    public final static String KEY_MEMBER_LOGIN = "key_member_login";
    public final static String KEY_ADMIN_LOGIN_SUCCESS = "key_admin_login_success";

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {

        ServerHttpResponse response = exchange.getResponse();
        ServerHttpRequest request = exchange.getRequest();
        try {

            String path = request.getPath().toString();
            log.info("---->进入过滤器GatewayFilter path:{}, body {}", path, request.getBody());
            String admintoken = exchange.getRequest().getHeaders().getFirst(TokenEnum.Admin.name());
            String h5token = exchange.getRequest().getHeaders().getFirst(TokenEnum.h5.name());
            String minitoken = exchange.getRequest().getHeaders().getFirst(TokenEnum.mini.name());
            String awstoken = exchange.getRequest().getHeaders().getFirst(TokenEnum.authen.name()); // SQS Event

            log.info("--->admintoken {} , h5token {} , minitoken {}  ", admintoken, h5token, minitoken);

            if (StringUtils.hasText(admintoken)) {

                Claims claims = jwtUtils.verifyToken(admintoken); // JWT不需要转码
                log.info("--->claims:{}", claims);
                String user = (String) claims.get(KEY_ADMIN_LOGIN_SUCCESS);
                log.info("--->后端头部解析user {}", user);
                
                JSONObject userObj = JSONObject.parseObject(user);
                JSONArray roles = userObj.getJSONArray("roles");
                Collection<GrantedAuthority> authorities = new ArrayList<>();
                for (int i = 0; i < roles.size(); i++) {
                    String role = roles.getString(i);
                    GrantedAuthority authority = new SimpleGrantedAuthority(role);
                    authorities.add(authority);
                }
                String adminToken = URLEncoder.encode(userObj.toJSONString(), "UTF-8"); //UTF-8转码
                log.info("---->后端头部转发 token {} ", adminToken);
                String username = userObj.getString("username");
                Authentication authentication = new UsernamePasswordAuthenticationToken(username, admintoken, authorities);
                // 每次请求都更新SecurityContextHolder.getContext()
                SecurityContextHolder.getContext().setAuthentication(authentication);
                log.info("---->管理员ROLES状态保持成功<-----");
                JSONObject haderMap = new JSONObject().fluentPut("key", TokenEnum.admintoken.name()).fluentPut("value", adminToken);
                return forward(exchange, chain, haderMap);


            } else {

                return chain.filter(exchange);
            }


        } catch (Exception e) {


            if (e instanceof ExpiredJwtException) {

                log.info("--->Token过期了<-----");
                return this.writeErrorMessage(ResEnum.token_expired.getCode(), response, HttpStatus.INTERNAL_SERVER_ERROR, "Token已过期");
            }
            log.error(StackTool.error(e, 100));

            return this.writeErrorMessage(CODE_OP_FAIL, response, HttpStatus.INTERNAL_SERVER_ERROR, e.getMessage());

        }
    }

    protected Mono<Void> writeErrorMessage(String code, ServerHttpResponse response, HttpStatus status, String msg) {

        JSONObject base = new JSONObject();
        base.put(ResEnum.resCode.name(), code);
        base.put(ResEnum.resMsg.name(), msg);
        String body = JSONObject.toJSONString(base);
        DataBuffer dataBuffer = response.bufferFactory().wrap(body.getBytes(StandardCharsets.UTF_8));
        response.getHeaders().set("content-Type", "application/json;charset=UTF-8");
        return response.writeWith(Mono.just(dataBuffer));
    }

    @Override
    public int getOrder() {
        return 10103;
    }


    private Mono<Void> forward(ServerWebExchange exchange, WebFilterChain chain, JSONObject headerMap) {

        ServerHttpRequest request = exchange.getRequest();
        String forwardedUri = request.getURI().toString();
        URI originalUri = request.getURI();

        if (forwardedUri.startsWith("https")) {
            try {
                log.info("<--执行HTTPS转HTTP逻辑-->");
                ServerHttpRequest.Builder mutate = request.mutate();
                URI mutatedUri = new URI("http",
                        originalUri.getUserInfo(),
                        originalUri.getHost(),
                        originalUri.getPort(),
                        originalUri.getPath(),
                        originalUri.getQuery(),
                        originalUri.getFragment());
                if (headerMap != null) {

                    log.info(">---执行https头部转发<---");
                    String[] values = new String[]{headerMap.getString("value")};
                    mutate.uri(mutatedUri).header(headerMap.getString("key"), values);

                } else {

                    mutate.uri(mutatedUri);

                }

                ServerHttpRequest build = mutate.build();
                return chain.filter(exchange.mutate().request(build).build());

            } catch (Exception e) {

                log.error(StackTool.error(e, 100));
                throw new IllegalStateException(e.getMessage(), e);
            }
        } else {

            log.info("--->协议非HTTPS<-----");
            if (headerMap != null) {
                log.info("--->执行HTTP转发头部信息<-------");

                String[] values = new String[]{headerMap.getString("value")};

                ServerHttpRequest httpRequest = exchange.getRequest().mutate().header(headerMap.getString("key"), values[0])
                        .build();

                return chain.filter(exchange.mutate().request(httpRequest).build());

            } else {

                return chain.filter(exchange);

            }

        }


    }


}


```

注意， RBAC的鉴权逻辑在网关层实现。 这样设计的灵活性是可以集中在网关层管控下游多个微服务。

以下是spring-security 由帐号的角色集合roles实现权限校验的逻辑, 在网关层java注解配置好。源码参考如下：

```
package com.smart.rest.config.security.webflux;

import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import com.coding.dian.sdk.StackTool;
import com.coding.dian.sdk.constants.Constants;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import lombok.Data;
import lombok.extern.log4j.Log4j2;
import okhttp3.Response;
import okhttp3.ResponseBody;
import org.json.web.jwt.JwtUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.client.ServiceInstance;
import org.springframework.cloud.client.loadbalancer.LoadBalancerClient;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import java.net.URLDecoder;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Data
@Log4j2
@Component
public class MySecurityAuthenProvider implements AuthenticationProvider {

   private String userName;
   private String passWord;
   private List<String> roles;

   
   @Override
   public Authentication authenticate(Authentication authentication) throws AuthenticationException {

      try {

         String access_token = (String) authentication.getPrincipal();
         log.info("----> access_token:{}", access_token);

         JSONObject json =  JSONObject.parseObject(URLDecoder.decode(access_token,"UTF-8"));

         
         JSONArray roles = json.getJSONArray("roles");

         String userName =  json.getString("username");

         log.info("--->  userName : {}", userName);

         List<GrantedAuthority> authorities = new ArrayList<>();
         for(int i=0 ;i < roles.size(); i++) {

            String role = (String)roles.get(i);
            authorities.add(new SimpleGrantedAuthority(role));
         }

         log.info("--->  roles : {}", roles);
         return new MyAuthentication(userName, null, authorities, null);

      }catch(Exception e) {

          log.error(StackTool.error(e,100));
          if (e instanceof  ExpiredJwtException) {
             throw new RuntimeException("token过期");
          }
          throw new RuntimeException(e.getMessage());
      }

   }

   @Override
   public boolean supports(Class<?> authentication) {
      return true;
   }


}

```



## 1.2 微服务



微服务使用spring-cloud, 注册中心和配置中心均使用nacos,  与网关使用相同的spring版本。这儿不再累述。 网关和微服务均通过nacos注册中心注册，服务发现使用spring-cloud-starter-alibaba-nacos-discovery，可实现微服务高可用。


## 2  微信第三方平台小程序的设计 

第三方平台小程序简单来说，就是你开发一个完整的小程序，可以提供给有需求的第三方使用。



## 2.1 准备工作



见微信官方文档。平台必须搭建好第三方平台小程序，主要是平台处理微信推送的消息与事件接收的逻辑。可以参考微信官方开放文档第三方平台准备工作部分介绍。

微信官方API调用比较有规律，现以小程序API授权回调处理为例简单讲解一下处理逻辑。

  企业法人授权小程序API，平台方会接收到微信的推送。

API：    /wechat/event/wechat/event/grant/callback

```
/**
    * 第三方平台授权后的回调， 返回授权码，拿授权码获取授权信息
    * @param authorization_code
    * @param auth_code
    * @return
    */
@RequestMapping(value= {"/grant/callback"},method=RequestMethod.GET)
public JSONObject grantCallback(@RequestParam(value="auth_code", required = true) String auth_code)    {
   
   log.info("--->授权回调  auth_code:{}", auth_code );
   
   //授权码获取授权信息
   JSONObject jsonResult = wechatPlatformService.getApiQueryAuth(auth_code);
   log.info("小程序API授权回调 json:{}", jsonResult);


   
      JSONObject  authorization_info  = jsonResult.getJSONObject("authorization_info");
   String authorizer_appid= authorization_info.getString("authorizer_appid");
   String authorizer_access_token = authorization_info.getString("authorizer_access_token");
   String authorizer_refresh_token = authorization_info.getString("authorizer_refresh_token");
       int expires_in = authorization_info.getIntValue("expires_in");
  
       PlatformGrant grant = new  PlatformGrant();
       grant.setComponent_appid(wXBizMsgCrypt.getAppId());
       grant.setAuthorizer_access_token(authorizer_access_token);
       grant.setAuthorizer_appid(authorizer_appid);
       grant.setAuthorizer_refresh_token(authorizer_refresh_token);
       grant.setExpires_in(expires_in);
       wechatPlatformService.savePlatformGrant(grant);
       log.info("-->授权信息已保存<----");
   
   return jsonResult;

   
   
}

```

将用户的授权信息持久化到云端。 以下是wechatPlatformService.getApiQueryAuth(auth_code)的业务逻辑。





```
public JSONObject getApiQueryAuth(String authorization_code) {

    String component_access_token = getComponentAccessToken(wXBizMsgCrypt.getAppId());
    HttpHeaders headers = new HttpHeaders();
    MediaType type = MediaType.parseMediaType("application/json; charset=utf-8");
    headers.setContentType(type);
    headers.add("Accept", MediaType.APPLICATION_XML.toString());
    JSONObject reqBody = new JSONObject();
    reqBody.put("component_appid", wXBizMsgCrypt.getAppId());
    reqBody.put("authorization_code", authorization_code);

    HttpEntity<JSONObject> formEntity = new HttpEntity<JSONObject>(reqBody, headers);
    restTemplate.getMessageConverters().set(1, new StringHttpMessageConverter(StandardCharsets.UTF_8));
    String url = "https://api.weixin.qq.com/cgi-bin/component/api_query_auth?component_access_token=" + component_access_token;
    JSONObject result = restTemplate.postForObject(url, formEntity, JSONObject.class);
    log.info(">>>授权码获取授权信息 返回： result=" + result);
    return result;


}

```



## 2.2 代企业创建小程序 



微信代企业创建小程序这个功能的确很棒，大大降低了企业（或个体户）使用小程序的门槛。

### 2.2.1 代企业创建小程序的好处



（1） 不用每年交300元小程序审核费用；如果企业或个体户自己去创建小程序，流程手续复杂不说，还要每年交300元小程序（或公众号）审核费用。

（2） 微信提供了代企业创建小程序的接口，企业或个体户的法人可以填写小程序信息直接申请。

   业务过程是：企业或个体户通过平台小程序提供的接口填写小程序申请资料（法人微信号、小程序名称等信息）提交到微信官方，微信官方审核通过后会给商家法人推送一条微信链接，商家法人打开微信链接后进行身份认证即可开通，同时微信官方将审核结果推送给平台小程序，平台小程序收到推送后获取商家小程序的ID，即authorizer_appid进行持久化。

   这部分的设计如下：

   首先是表设计，见如下：

```
CREATE TABLE public.t_platform_grant (

id int8 NOT NULL,

component_appid varchar(20) NOT NULL,

authorizer_appid varchar(20) NOT NULL,

authorizer_access_token varchar(255) NULL,

expires_in int4 NULL,

authorizer_refresh_token varchar(255) NULL,

update_time varchar(19) NOT NULL,

company_name varchar(62) NULL,

contact_people varchar(12) NULL,

contact_tel varchar(12) NULL,

much_mini_name varchar(64) NULL,

qrcode_url varchar(200) NULL,

CONSTRAINT component_authorizer_appid_key UNIQUE (component_appid, authorizer_appid),

CONSTRAINT platform_grant_pkey PRIMARY KEY (id)

);

```



其中：authorizer_appid：是商家（想使用第三方平台小程序的企业或个体户）申请的小程序授权ID，这个值必须在第三方平台持久化。

authorizer_access_token和 authorizer_refresh_token分别是票据信息和刷新票据信息，刷新票据authorizer_refresh_token是在authorizer_access_token过期后用来申请新的票据信息。

这几个商家小程序参数平台方后面要反复使用到。

### 2.2.2 商家免费申请小程序通道

为了方便商家使用第三方小程序，第三方平台小程序方开发了一个界面录入，通过公众号进入即可申请。

可以通过以下通道进入自助申请：

进入 微信公众 号 “coding新零售" ,  进入菜单：产品/小程序自助开通。

也可以通过公众号二维码扫码进入，二维码如下：

![https://coding-2020.s3.cn-northwest-1.amazonaws.com.cn/assets/03.jpeg](https://coding-2020.s3.cn-northwest-1.amazonaws.com.cn/assets/03.jpeg)





 在二级页面进入： 自助服务/企业小程序快速创建



![https://coding-2020.s3.cn-northwest-1.amazonaws.com.cn/assets/04.jpeg](https://coding-2020.s3.cn-northwest-1.amazonaws.com.cn/assets/04.jpeg)







以下是企业小程序快速创建界面。



![https://coding-2020.s3.cn-northwest-1.amazonaws.com.cn/assets/05.jpeg](https://coding-2020.s3.cn-northwest-1.amazonaws.com.cn/assets/05.jpeg)



## 2.2 代商家小程序完成基本信息更新



企业小程序快速创建完成，微信审核后，平台小程序方后台可以完成其他信息的维护，

 如：名称修改、小程序图像、小程序简介等。 商家可以自助完成，也可以由平台管理员代完成。



![https://coding-2020.s3.cn-northwest-1.amazonaws.com.cn/assets/06.png](https://coding-2020.s3.cn-northwest-1.amazonaws.com.cn/assets/06.png)





## 2.3 代商家维护小程序整体功能介绍



先还是整体预览一下第三方平台小程序的功能。

平台方可以浏览所有的商家小程序列表。右边的”操作“栏处具体介绍一下： 



![https://coding-2020.s3.cn-northwest-1.amazonaws.com.cn/assets/07.png](https://coding-2020.s3.cn-northwest-1.amazonaws.com.cn/assets/07.png)



功能2:修改小程序的基本信息

![https://coding-2020.s3.cn-northwest-1.amazonaws.com.cn/assets/08.png](https://coding-2020.s3.cn-northwest-1.amazonaws.com.cn/assets/08.png)





功能3: 上传小程序隐私



功能4: 上传小程序生成体验码



![https://coding-2020.s3.cn-northwest-1.amazonaws.com.cn/assets/09.png](https://coding-2020.s3.cn-northwest-1.amazonaws.com.cn/assets/09.png)







功能5: 小程序插件管理



![https://coding-2020.s3.cn-northwest-1.amazonaws.com.cn/assets/10.png](https://coding-2020.s3.cn-northwest-1.amazonaws.com.cn/assets/10.png)





功能6: 生成小程序体验版

提交成功后，生成小程序的二维码，扫码即可体验。在开发阶段此功能非常有用，可以验证准线上环境的体验。

以下功能通过生成体验码并向小程序传参。如：门店点餐桌位号。 



![https://coding-2020.s3.cn-northwest-1.amazonaws.com.cn/assets/11.png](https://coding-2020.s3.cn-northwest-1.amazonaws.com.cn/assets/11.png)





功能7: 小程序提交审核

功能8： 小程序分类设置

此功能调用了微信官方的接口，实现二级联动的效果。

![https://coding-2020.s3.cn-northwest-1.amazonaws.com.cn/assets/13.png](https://coding-2020.s3.cn-northwest-1.amazonaws.com.cn/assets/13.png)



功能9: 小程序地理位置申请

如果小程序使用了地理位置，一定要提交申请，未提交申请或审核不通过，小程序无法使用地理位置信息。



![https://coding-2020.s3.cn-northwest-1.amazonaws.com.cn/assets/14.png](https://coding-2020.s3.cn-northwest-1.amazonaws.com.cn/assets/14.png)



功能10: 商家小程序体验者设置

功能11: 小程序最后一次申请状态查询及取消



![https://coding-2020.s3.cn-northwest-1.amazonaws.com.cn/assets/15.png](https://coding-2020.s3.cn-northwest-1.amazonaws.com.cn/assets/15.png)



功能12: 小程序发布

当小程序审核通过后就可以发布小程序了

功能13: 小程序域名设置

 小程序域名设置需要获取校验文件，将校验文件部署到指定的域名路径下。



![https://coding-2020.s3.cn-northwest-1.amazonaws.com.cn/assets/16.png](https://coding-2020.s3.cn-northwest-1.amazonaws.com.cn/assets/16.png)





功能14: 小程序草稿

可以代商家小程序删除草稿或者添加到模板

![https://coding-2020.s3.cn-northwest-1.amazonaws.com.cn/assets/17.png](https://coding-2020.s3.cn-northwest-1.amazonaws.com.cn/assets/17.png)



# 3 门店/商品SKU设计

## 3.1 门店

门店的设计可以简单介绍。平台按多租户设计，一个租户可以建多个门店。门店信息主要是基本信息、地图位置、配送（最大配送距离、起送价、配送费用）、打印机设置等通用的设置能力。 通过step 组件分几步来完成。

 商家登录平台后，左边的门店导航栏即可进入门店管理页面。



![https://coding-2020.s3.cn-northwest-1.amazonaws.com.cn/assets/18.png](https://coding-2020.s3.cn-northwest-1.amazonaws.com.cn/assets/18.png)



## 3.2 商品分类

商品二级分类就够了。需要手动排序、显示关联的SKU。 SKU作用在一级分类上。



![https://coding-2020.s3.cn-northwest-1.amazonaws.com.cn/assets/19.png](https://coding-2020.s3.cn-northwest-1.amazonaws.com.cn/assets/19.png)





## 3.3 商品基础信息



![https://coding-2020.s3.cn-northwest-1.amazonaws.com.cn/assets/19B.png](https://coding-2020.s3.cn-northwest-1.amazonaws.com.cn/assets/19B.png)



## 3.4 商品SKU 



![https://coding-2020.s3.cn-northwest-1.amazonaws.com.cn/assets/21.png](https://coding-2020.s3.cn-northwest-1.amazonaws.com.cn/assets/21.png)



## 3.5 设置库存



库存设置，如： 仅一个维度，包装（1支装、2支装），展示效果如下： 



![https://coding-2020.s3.cn-northwest-1.amazonaws.com.cn/assets/22.png](https://coding-2020.s3.cn-northwest-1.amazonaws.com.cn/assets/22.png)



若SKU有三个维度， 如： 包装（1 支装、2 支装、3支装）有3个属性值、产地 （顺德陈村、顺德大良）有2个属性值、档次（标准、高档）有2个属性，那就会产生 3X2X2 = 12个商品最小单元（SKU）， 一个商品有12个SKU需要定义价格及库存。如下图 ：





![https://coding-2020.s3.cn-northwest-1.amazonaws.com.cn/assets/23.png](https://coding-2020.s3.cn-northwest-1.amazonaws.com.cn/assets/23.png)





## 3.5 订单

订单支持在店消费及配送。 可以按时间段、按订单号及订单状态来查询。 

也可以查看订单的详情。

![https://coding-2020.s3.cn-northwest-1.amazonaws.com.cn/assets/24.png](https://coding-2020.s3.cn-northwest-1.amazonaws.com.cn/assets/24.png)





# 4 小程序



## 4.1 首页设计



首页进入商家小程序，首先是门店列表及距离信息。 由小程序与门店的关联可以获取与小程序关联的所有门店。 通过高德地图来获取定位。 适合辖锁店模式或者一个老板多个分店。在商家小程序中可以按照位置来排序。



![https://coding-2020.s3.cn-northwest-1.amazonaws.com.cn/assets/25.jpeg](https://coding-2020.s3.cn-northwest-1.amazonaws.com.cn/assets/25.jpeg)





## 4.2 商品页



小程序商品页列出门店的所有商品列表。 可以通过醒目的汽泡来提醒各分类商品已选购的数量。









![https://coding-2020.s3.cn-northwest-1.amazonaws.com.cn/assets/26.jpeg](https://coding-2020.s3.cn-northwest-1.amazonaws.com.cn/assets/26.jpeg)





商品详情页：

对于有规格的商品，需要从商品的SKU表中加载：



![https://coding-2020.s3.cn-northwest-1.amazonaws.com.cn/assets/27.jpeg](https://coding-2020.s3.cn-northwest-1.amazonaws.com.cn/assets/27.jpeg)







以下是商品详情页的数据结构： （最多支持3个维度， SKU维度遵循笛卡尔集，事实上电商应用中很少超过3个维度的）， 前端要实现上图商品详情页的效果，需要算法。



```
{"keys":[{"key_id":"10494","values":[{"value_id":10497,"value":"1支装"},{"value_id":10496,"value":"2支装"},{"value_id":10495,"value":"3支装"}],"key":"包装"},{"key_id":"10498","values":[{"value_id":10500,"value":"顺德陈村"},{"value_id":10499,"value":"顺德大良"}],"key":"产地 "},{"key_id":"10501","values":[{"value_id":10502,"value":"标准"},{"value_id":10503,"value":"高档"}],"key":"档次"}],"values":[{"standard_price":1.00,"skus":[{"value_id":10497,"value":"1支装"},{"value_id":10500,"value":"顺德陈村"},{"value_id":10502,"value":"标准"}],"underline_price":1.10,"value_ids":[10497,10500,10502],"stock":"30","sale_price":1.00},{"standard_price":1.00,"skus":[{"value_id":10497,"value":"1支装"},{"value_id":10500,"value":"顺德陈村"},{"value_id":10503,"value":"高档"}],"underline_price":1.10,"value_ids":[10497,10500,10503],"stock":"30","sale_price":1.00},{"standard_price":1.00,"skus":[{"value_id":10497,"value":"1支装"},{"value_id":10499,"value":"顺德大良"},{"value_id":10502,"value":"标准"}],"underline_price":1.10,"value_ids":[10497,10499,10502],"stock":"30","sale_price":1.00},{"standard_price":1.00,"skus":[{"value_id":10497,"value":"1支装"},{"value_id":10499,"value":"顺德大良"},{"value_id":10503,"value":"高档"}],"underline_price":1.10,"value_ids":[10497,10499,10503],"stock":"30","sale_price":1.00},{"standard_price":1.00,"skus":[{"value_id":10496,"value":"2支装"},{"value_id":10500,"value":"顺德陈村"},{"value_id":10502,"value":"标准"}],"underline_price":1.10,"value_ids":[10496,10500,10502],"stock":"30","sale_price":1.00},{"standard_price":1.00,"skus":[{"value_id":10496,"value":"2支装"},{"value_id":10500,"value":"顺德陈村"},{"value_id":10503,"value":"高档"}],"underline_price":1.10,"value_ids":[10496,10500,10503],"stock":"30","sale_price":1.00},{"standard_price":1.00,"skus":[{"value_id":10496,"value":"2支装"},{"value_id":10499,"value":"顺德大良"},{"value_id":10502,"value":"标准"}],"underline_price":1.10,"value_ids":[10496,10499,10502],"stock":"30","sale_price":1.00},{"standard_price":1.00,"skus":[{"value_id":10496,"value":"2支装"},{"value_id":10499,"value":"顺德大良"},{"value_id":10503,"value":"高档"}],"underline_price":1.10,"value_ids":[10496,10499,10503],"stock":"30","sale_price":1.00},{"standard_price":1.00,"skus":[{"value_id":10495,"value":"3支装"},{"value_id":10500,"value":"顺德陈村"},{"value_id":10502,"value":"标准"}],"underline_price":1.10,"value_ids":[10495,10500,10502],"stock":"30","sale_price":1.00},{"standard_price":1.00,"skus":[{"value_id":10495,"value":"3支装"},{"value_id":10500,"value":"顺德陈村"},{"value_id":10503,"value":"高档"}],"underline_price":1.10,"value_ids":[10495,10500,10503],"stock":"30","sale_price":1.00},{"standard_price":1.00,"skus":[{"value_id":10495,"value":"3支装"},{"value_id":10499,"value":"顺德大良"},{"value_id":10502,"value":"标准"}],"underline_price":1.10,"value_ids":[10495,10499,10502],"stock":"30","sale_price":1.00},{"standard_price":1.00,"skus":[{"value_id":10495,"value":"3支装"},{"value_id":10499,"value":"顺德大良"},{"value_id":10503,"value":"高档"}],"underline_price":1.10,"value_ids":[10495,10499,10503],"stock":"30","sale_price":1.00}],"resCode":"0","resMsg":"success"}

```





## 4.3 购物车



购物车的实现基本原则是 map 结构，为了达到最佳性能，购物车操作不需要与服务端交互，数据在小程序本地端存储。 



![https://coding-2020.s3.cn-northwest-1.amazonaws.com.cn/assets/28.jpeg](https://coding-2020.s3.cn-northwest-1.amazonaws.com.cn/assets/28.jpeg)





提交订单前，服务器会检测微信用户有无登录。如果没有登录，将弹出登录提示。而不是一

进入小程序就要求用户微信登录。 



![https://coding-2020.s3.cn-northwest-1.amazonaws.com.cn/assets/29.jpeg](https://coding-2020.s3.cn-northwest-1.amazonaws.com.cn/assets/29.jpeg)





授权后，可以获取微信用户的openid。 服务器将openid放在JWT token 中加密存储。调用微信统一下单后需要用到这个token。

以下是提交统一下单的购物车数据结构 :

```
{"delivery_fix":"0.01","total_price":"1.01","delivery":"2","shopid":8804,"openid":"ojM8n5G69FSxi348Cu1aBefp_3c04","tableNo":1,"nickname":"微信用户","mers":[{"image":"https://s3.cn-northwest-1.amazonaws.com.cn/coding-2020/merchandise/10091/20230109_bb80a544-ccc3-41f7-a53d-7edf4774ed9c.png","thumb_path":"https://s3.cn-northwest-1.amazonaws.com.cn/coding-2020/merchandise/10091/90/90/20230109_bb80a544-ccc3-41f7-a53d-7edf4774ed9c.png","unit":"只","sortid":10087,"price":"1.00","keys":[{"key_id":10494,"key":"包装"},{"key_id":10498,"key":"产地 "},{"key_id":10501,"key":"档次"}],"name":"夏季玫瑰","shopid":8804,"sort":"情人节主题","id":10091,"selectedCount":1,"haslabel":"yes","label":"1支装 顺德大良 标准 ","stock":"30","underline_price":1.1,"sale_price":1,"standard_price":1,"symbol":"10497,10499,10502","key":"10091-10497,10499,10502","label_price":"1-1","selected":true,"itemPrice":"1.00","counts":[],"count":1}],"address":{"name":"张大帅","mobile":"13311111111","province":"天津市","city":"天津市","postcode":"572000","nationalcode":"120103","detail":"天津市天津市河西区梅江街道126号","district":"河西区","location":"117.215914,39.062842"}}

```



小程序为兼容到店消费（如：点餐中的堂食）和物流配送 （部分商家是愿意在半径范围内自行配送的）。 在用户提交订单前对消费模式作进一步确认。



![https://coding-2020.s3.cn-northwest-1.amazonaws.com.cn/assets/30.jpeg](https://coding-2020.s3.cn-northwest-1.amazonaws.com.cn/assets/30.jpeg)









选择物流配送后，接下来需要用户填写配送信息。 小程序可以直接调用微信官方的收件地址功能 ，这一点节省了开发者大量的开发时间，为微信点赞。

接下来就是支付环节，将再下一个章节进行讲解。



![https://coding-2020.s3.cn-northwest-1.amazonaws.com.cn/assets/31.jpeg](https://coding-2020.s3.cn-northwest-1.amazonaws.com.cn/assets/31.jpeg)









支付（这里的支付动作包括调用微信统一下单接口、平台保存订单及配送信息）。



支付之前调用高德地图计算用户的收件地址距离门店的距离。距离超出门店的最大配送半径将弹出提示。



![https://coding-2020.s3.cn-northwest-1.amazonaws.com.cn/assets/32.jpeg](https://coding-2020.s3.cn-northwest-1.amazonaws.com.cn/assets/32.jpeg)







## 4.4 订单设计





设计过电商应用的同行应该遇到过这个问题，就是用户在下单后没有支付，此时，系统中存在大量未支付的订单数据，不排队有恶意提交的订单数据。良好的订单设计要及时清理系统多余的订单数据而不影响系统的性能，同时要实现订单倒计时，如：下单后15分钟不支付将作废，系统要将废弃的订单删除。

用户点击“订单”菜单，可以看到订单列表的Tab页。



![https://coding-2020.s3.cn-northwest-1.amazonaws.com.cn/assets/33.jpeg](https://coding-2020.s3.cn-northwest-1.amazonaws.com.cn/assets/33.jpeg)









订单详情界面：

 对于未及时支付的订单有一个倒计时器。 



![https://coding-2020.s3.cn-northwest-1.amazonaws.com.cn/assets/34.png](https://coding-2020.s3.cn-northwest-1.amazonaws.com.cn/assets/34.png)





订单设计见以下时序图（简单画了下）。具体的实现是：用户提交订单至第三方小程序平台，平台保存订单后，延迟14分50秒发送异步订单删除消息给AWS，AWS lambda 函数触发后向平台方发送HTTP请求删除订单， 平台方判断订单有无支付，如果没有支付就直接删除。

![https://coding-2020.s3.cn-northwest-1.amazonaws.com.cn/assets/35.png](https://coding-2020.s3.cn-northwest-1.amazonaws.com.cn/assets/35.png)









异步删除订单消息使用AWS SQS（按量计费）也可以用阿里云rocketMQ来代替。 



## 4.5 门店导航



门店导航对于消费者而言非常重要。 消费者订了餐后要驱车前往，如果提供门店地图那简直是锦上添花。



![https://coding-2020.s3.cn-northwest-1.amazonaws.com.cn/assets/36.jpeg](https://coding-2020.s3.cn-northwest-1.amazonaws.com.cn/assets/36.jpeg)





点击门店地图导航，直接弹出地图选项。 



![https://coding-2020.s3.cn-northwest-1.amazonaws.com.cn/assets/37.jpeg](https://coding-2020.s3.cn-northwest-1.amazonaws.com.cn/assets/37.jpeg)



用户也可以点“到店出行方案”来计算详细的路径及时长。



![https://coding-2020.s3.cn-northwest-1.amazonaws.com.cn/assets/38.jpeg](https://coding-2020.s3.cn-northwest-1.amazonaws.com.cn/assets/38.jpeg)





# 5 微信小程序模板消息推送设计

在一些电商场景中或扫码点餐的场景中， 用户微信下单付款后，需要向微信用户推送消息，如：付款成功提醒或者取餐提醒等模板消息。

由第三方平台向微信用户发送模板消息提醒需要干几件事。







在微信小程序中，需要微信用户订阅消息模板。







第三方平台小程序可以应用于有零售、电商 、扫码点餐需求的商家。而且是免费的。

有兴趣了解可以加微信： comeon_betty  或关注公众号。



![https://coding-2020.s3.cn-northwest-1.amazonaws.com.cn/assets/03.jpeg](https://coding-2020.s3.cn-northwest-1.amazonaws.com.cn/assets/03.jpeg) 

# 







同时希望志同道合的朋友一起来共同完善，业余时间做一些产品研究。

个人微信二维码：

![https://coding-2020.s3.cn-northwest-1.amazonaws.com.cn/assets/39.jpeg](https://coding-2020.s3.cn-northwest-1.amazonaws.com.cn/assets/39.jpeg)





