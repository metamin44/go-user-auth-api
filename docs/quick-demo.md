# Quick Demo

This guide demonstrates how to start the Go User Authentication API,
verify the running services, register a user, authenticate, and access
a protected endpoint.

## Prerequisites

- Docker Desktop or Docker Engine with Docker Compose.
- curl.
- jq (for extracting the access token from the login response).

## 1. Start the application

Copy the example environment file:

    cp .env.example .env

Review the `.env` file and configure the required secrets and database
settings before starting the application.

Build and start all services:

    docker compose up --build -d

Check the service status:

    docker compose ps

## 2. Verify the services

Open the Swagger UI:

- App 1: http://localhost:8085/swagger/index.html
- App 2: http://localhost:8086/swagger/index.html

Check the Prometheus metrics endpoint:

    curl http://localhost:8085/metrics

## 3. Register a user

Use a unique email address and phone number for each registration.

    curl -X POST http://localhost:8085/register \
      -H "Content-Type: application/json" \
      -d '{
        "name": "John Doe",
        "email": "john.demo@example.com",
        "phone": "09123456789",
        "password": "Secret123!"
      }'

A successful registration returns HTTP 201.

## 4. Log in

    LOGIN_RESPONSE=$(curl -sS -X POST http://localhost:8085/login \
      -H "Content-Type: application/json" \
      -d '{
        "email": "john.demo@example.com",
        "password": "Secret123!"
      }')

    echo "$LOGIN_RESPONSE" | jq .

Extract the access token:

    ACCESS_TOKEN=$(printf '%s' "$LOGIN_RESPONSE" | jq -r '.data.access_token')

## 5. Access a protected endpoint

Use the access token to retrieve the user's profile:

    curl -X GET http://localhost:8085/auth/profile \
      -H "Authorization: Bearer $ACCESS_TOKEN"

A successful request returns the authenticated user's profile.

## 6. Stop the services

Stop the containers:

    docker compose down

To remove the database volume as well, use:

    docker compose down -v

**Warning:** The `-v` option deletes persistent database data.
