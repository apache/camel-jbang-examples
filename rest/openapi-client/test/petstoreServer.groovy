import org.springframework.http.HttpStatus

endpoints {
    http('petstoreServer')
            .server()
            .port(8080)
            .defaultStatus(HttpStatus.CREATED)
            .autoStart(true)
}
