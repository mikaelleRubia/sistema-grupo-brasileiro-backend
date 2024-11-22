FROM ubuntu:latest AS build

RUN apt-get update
RUN apt-get install openjdk-17-jdk -y
COPY . .
RUN apt-get install maven -y
RUN mvn clean install

FROM openjdk:17-jdk-slim

EXPOSE 8081


COPY target/sistema-grupo-brasileiro-backend-0.0.1-SNAPSHOT.jar /app/app.jar

RUN chmod 644 /app/app.jar

# Copiar e configurar a chave privada
COPY cepedi.pem /etc/ssl/private/cepedi.pem
RUN chmod 600 /etc/ssl/private/cepedi.pem

# Configurar diretório de uploads
RUN mkdir -p /home/ec2-user/upload && chmod 700 /home/ec2-user/upload && chown -R root:root /home/ec2-user/upload

# Configurar entrada
CMD ["sh", "-c", "java -jar /app/app.jar"]


