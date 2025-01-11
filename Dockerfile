FROM golang:1.20 AS builder
WORKDIR /app
RUN apt-get update && apt-get install -y git
RUN git clone https://github.com/DoctorW00/goSFDLSauger.git .
RUN go build -o goSFDLSauger goSFDLSauger.go sfdl.go ftp.go unpacker.go webserver.go mqtt.go .
FROM alpine:latest  
COPY --from=builder /app/goSFDLSauger /goSFDLSauger
CMD ["/goSFDLSauger"]
