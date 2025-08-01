# Dockerfile

FROM golang:1.24.3-alpine

# Install necessary build tools
RUN apk add --no-cache gcc g++ make

# Set working directory
WORKDIR /app

# Copy go mod and sum files
COPY go.mod ./
COPY go.sum ./

# Download dependencies
RUN go mod download

# Copy the source code
COPY . .
COPY ./docs ./docs

# Build the application
RUN go build -o main .

# Expose port
EXPOSE 8082

# Run the app
CMD ["./main"]