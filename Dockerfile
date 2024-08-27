# Use an official OpenJDK runtime as a parent image with Java 17
FROM openjdk:17-jdk-slim

# Set the working directory inside the container
WORKDIR /app

# Copy the Spring Boot application JAR file into the container
COPY target/demolevan-0.0.1-SNAPSHOT.jar /app/demolevan-0.0.1-SNAPSHOT.jar

# Expose the port that your application will run on
EXPOSE 8080

# Define the command to run your application
ENTRYPOINT ["java", "-jar", "/app/demolevan-0.0.1-SNAPSHOT.jar"]
