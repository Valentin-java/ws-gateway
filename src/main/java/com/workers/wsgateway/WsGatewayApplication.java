package com.workers.wsgateway;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;

@SpringBootApplication
@EnableDiscoveryClient
public class WsGatewayApplication {

	public static void main(String[] args) {
		SpringApplication.run(WsGatewayApplication.class, args);
	}

}
