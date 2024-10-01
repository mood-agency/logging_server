# Etapa 1: Compilación
FROM golang:1.22-alpine AS builder

# Establece el directorio de trabajo dentro del contenedor
WORKDIR /app

# Copia los archivos de go.mod y go.sum y descarga las dependencias
COPY go.mod go.sum ./
RUN go mod download

# Copia el código fuente
COPY . .

# Compila la aplicación con enlazado estático
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o loggin-server .

# Etapa 2: Imagen final
FROM alpine:3.18

# Instala certificados CA y otras dependencias necesarias
RUN apk add --no-cache ca-certificates tzdata

# Copia el binario compilado desde la etapa de compilación
COPY --from=builder /app/loggin-server /app/loggin-server

# Establece los permisos correctos
RUN chmod +x /app/loggin-server

# Establece el directorio de trabajo
WORKDIR /app

# Exponer el puerto
EXPOSE 8080

# Instala dumb-init para manejar los procesos en el background
RUN apk add dumb-init
ENTRYPOINT ["/usr/bin/dumb-init", "--"]

# Comando para ejecutar la aplicación
CMD ["/app/loggin-server"]

