FROM ubuntu:latest AS build

RUN apt-get update

RUN apt-get install openjdk-17-jdk -y
COPY . .

RUN apt-get install maven -y
RUN mvn clean install

FROM openjdk:17-jdk-slim

ENV JAVA_OPTS="-Djava.util.prefs.userRoot=/dev/null -Djava.util.prefs.systemRoot=/dev/null"
EXPOSE 8080

COPY --from=build /target/sistema-grupo-brasileiro-backend-0.0.1-SNAPSHOT.jar .

# Copia e configura a chave privada
COPY cepedi.pem /etc/ssl/private/cepedi.pem
RUN chmod 600 /etc/ssl/private/cepedi.pem

# Configuração do diretório de uploads
RUN mkdir -p /home/ec2-user/upload && chmod 700 /home/ec2-user/upload && chown -R root:root /home/ec2-user/upload

# Limpeza do apt
RUN apt-get clean && rm -rf /var/lib/apt/lists/*


ENTRYPOINT ["sh", "-c", "java $JAVA_OPTS -jar /sistema-grupo-brasileiro-backend-0.0.1-SNAPSHOT.jar --server.port=${PORT:-8080}"]
