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

# Copiando a chave privada e definindo permissões
# Copia a chave privada e define permissões (caso necessário para a aplicação)
COPY /certificates/cepedi.pem /etc/ssl/private/cepedi.pem
RUN chmod 600 /etc/ssl/private/cepedi.pem

# Configuração do diretório de uploads
RUN mkdir -p /uploads && chmod 777 /uploads && chown -R root:root /uploads


# Criando o diretório para o upload dos arquivos e configurando as permissões
RUN mkdir -p /uploads && chmod 777 /uploads

# Garantir que o processo tem permissão para acessar
RUN chown -R root:root /uploads

ENTRYPOINT ["sh", "-c", "java $JAVA_OPTS -jar /sistema-grupo-brasileiro-backend-0.0.1-SNAPSHOT.jar --server.port=${PORT:-8080}"]
