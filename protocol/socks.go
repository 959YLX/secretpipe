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

// Implementation socks5 protocol

package protocol

import (
	"errors"
	"net"

	"github.com/sirupsen/logrus"
)

const (
	bufferCapacity = 64
)

var (
	authMethodNotSupportError = errors.New("Socks5 Auth method not supported")
)

/*
 SOCKS5 check protocol
 Request:
 +----------------------+
 |VER| NMETHODS| METHODS|
 +----------------------+
 Response:
 +-----------+
 |VER| METHOD|
 +-----------+
*/

// Socks5CheckRequest socks5 communication request
type Socks5CheckRequest struct {
	VER      byte
	NMETHODS byte
	METHODS  []byte
}

// Socks5CheckResponse socks5 communication response
type Socks5CheckResponse struct {
	VER    byte
	METHOD byte
}

/*
 SOCKS5 Data protocol
 Request:
 +---------------------------------------+
 |VER| CMD| RSV| ATYP| DST.ADDR| DST.PORT|
 +---------------------------------------+
 Response:
 +---------------------------------------+
 |VER| REP| RSV| ATYP| BND.ADDR| BND.PORT|
 +---------------------------------------+
*/

// Socks5DataRequest socks5 data request
type Socks5DataRequest struct {
	VER  byte
	CMD  byte
	RSV  byte
	ATYP byte
	DST  []byte
}

// Socks5DataResponse socks5 data response
type Socks5DataResponse struct {
	VER  byte
	REP  byte
	RSV  byte
	ATYP byte
	BND  []byte
}

/*
   +----+------+----------+------+----------+
   |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
   +----+------+----------+------+----------+
   | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
   +----+------+----------+------+----------+
*/

// Socks5AuthenticationRequest socks5 Authentication protocol request
type Socks5AuthenticationRequest struct {
	VER    byte
	ULEN   byte
	UNAME  []byte
	PLEN   byte
	PASSWD []byte
}

// Socks5AuthenticationResponse socks5 Authentication protocol response
type Socks5AuthenticationResponse struct {
	VER    byte
	STATUS byte
}

// Socks5LifeCycle socks5 life cycle flag
type Socks5LifeCycle int8

const (
	WaitInit    Socks5LifeCycle = 0
	WaitAuth    Socks5LifeCycle = 1
	Transfering Socks5LifeCycle = 2
	Closed      Socks5LifeCycle = 3
)

// Socks5 socks5 object, every socks connection's life cycle is managed by a object
type Socks5 struct {
	activity   bool
	isAuth     bool
	conn       *net.Conn
	lifeStatus Socks5LifeCycle
}

// NewSocks5 create socks5 proxy object
func NewSocks5(conn *net.Conn) (*Socks5, error) {
	if conn == nil {
		return nil, errors.New("Connection object is nil")
	}
	return &Socks5{
		activity:   true,
		isAuth:     false,
		conn:       conn,
		lifeStatus: WaitInit,
	}, nil
}

func (socks *Socks5) Service() error {
	if socks.conn == nil || socks.lifeStatus == Closed {
		return errors.New("Cannot service closed connection")
	}
	go func() {
		for socks.lifeStatus != Closed {
			switch socks.lifeStatus {
			case WaitInit:
				socks.initSocks5()
			case WaitAuth:

			}
		}
	}()
	return nil
}

func (socks *Socks5) initSocks5() error {
	buf := make([]byte, 8)
	readedByte, err := (*socks.conn).Read(buf)
	if err != nil || readedByte < 3 {
		// error
		return errors.New("Read init header error")
	}
	socks5Version := buf[0]
	if socks5Version != 0x05 {
		return errors.New("Socks protocol version should be socks5")
	}
	socks5MethodNumber := buf[1]
	for methodIndex := 0; methodIndex < int(socks5MethodNumber); methodIndex++ {
		supportMethod := buf[methodIndex+2]
		switch supportMethod {
		case 0x00:
			// NO AUTHENTICATION REQUIRED
			return authMethodNotSupportError
		case 0x02:
			// USERNAME/PASSWORD
			logrus.Debug("Client support username auth")
		case 0xFF:
			//  NO ACCEPTABLE METHODS
			return authMethodNotSupportError
		default:
			return authMethodNotSupportError
		}
	}
	// build response package
	response := []byte{0x05, 0x02}
	// TODO
	(*socks.conn).Write(response)
	socks.lifeStatus = WaitAuth
	return nil
}

func (socks *Socks5) authSocks5() (bool, error) {
	return false, nil
}
