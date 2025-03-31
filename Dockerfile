# Etapa de construcción con Maven y Java 8
FROM maven:3.9.6-eclipse-temurin-8-alpine AS build

WORKDIR /app

# Copiar archivos del proyecto y compilar
COPY pom.xml . 
COPY src ./src

RUN mvn clean package -DskipTests

# Etapa de producción con Java 8
FROM openjdk:8-jdk-alpine  

WORKDIR /app

COPY --from=build /app/target/*.jar app.jar

ENV JAVA_OPTS="-Xmx512m -Xms128m -XX:+UseContainerSupport"

EXPOSE 8081

ENTRYPOINT ["sh", "-c", "java $JAVA_OPTS -jar app.jar"]
