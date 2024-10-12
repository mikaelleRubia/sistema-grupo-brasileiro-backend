FROM ubuntu:latest AS build

RUN apt-get update

RUN apt-get install openjdk-17-jdk -y
COPY . .

RUN apt-get install maven -y
RUN mvn clean install

FROM openjdk:17-jdk-slim

ENV JAVA_OPTS="-Djava.util.prefs.userRoot=/dev/null -Djava.util.prefs.systemRoot=/dev/null"

EXPOSE 8080

COPY --from=build /target/ .

ENTRYPOINT ["java", "-jar", "sistema-grupo-brasileiro-backend-0.0.1-SNAPSHOT.jar"]