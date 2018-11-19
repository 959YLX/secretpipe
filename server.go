// Copyright [2018] [959YLX]

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

// 	http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"errors"
	"net"

	proc "github.com/959YLX/secretpipe/protocol"

	"github.com/sirupsen/logrus"
)

const (
	spipeProtocol = "spipe"
)

// StartServer 启动服务端
func StartServer() {
	LoadConfig()
	listeners := PipeConfig.Pipe.Server.Listeners
	for _, listener := range listeners {
		go startListener(listener.Protocol, listener.IP, listener.Port)
	}
}

func startListener(protocol string, ip string, port int) error {
	defer func() {
		recover()
	}()
	tcpListener, err := net.ListenTCP("tcp", &net.TCPAddr{
		IP:   net.ParseIP(ip),
		Port: port,
	})
	if err != nil {
		return errors.New("Listen tcp error")
	}
	for {
		conn, err := tcpListener.Accept()
		if err != nil {
			logrus.WithError(err).Error("Accept tcp connection failed")
			continue
		}
		switch protocol {
		case spipeProtocol:
			proc.NewSpipe(&conn, true)
		}
	}
}
