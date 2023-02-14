package utils

import (
	"net/http"
	"strconv"
)

func GetLocalHTTPServer(port int, handlerF http.HandlerFunc, path string) *http.Server {
	httpServer := &http.Server{Addr: "localhost:" + strconv.Itoa(port)}
	http.Handle("/checkfile", handlerF)
	return httpServer
}
