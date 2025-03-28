FROM maven:3.9.6-eclipse-temurin-17-alpine AS build

WORKDIR /app

#Copiar archivos del proyecto y compilar

COPY pom.xml .

COPY src ./src

RUN mvn clean package -DskipTests

FROM openjdk:8-jdk-alpine 

# Establecer el directorio de trabajo del contenedor
WORKDIR /app

COPY --from=build /app/target/*.jar app.jar

EXPOSE 8081

ENTRYPOINT ["java", "-jar", "app.jar"]