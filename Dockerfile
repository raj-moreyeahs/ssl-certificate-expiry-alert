FROM golang:latest AS build

WORKDIR /app

COPY go.mod ./

RUN go mod download

COPY . .

RUN go build -o main .

FROM golang:latest AS runtime

WORKDIR /app

COPY --from=build /app/main .

EXPOSE 8080

CMD ["./main"]
