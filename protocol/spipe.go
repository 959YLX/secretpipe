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

// Implementation spipe protocol

package protocol

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"

	"github.com/sirupsen/logrus"
)

/*
 +---------------------+
 |VER| DSIZE| CMD| DATA|
 | 1 |   4  |  1 | ver |
 +---------------------+
*/

// Spipe spipe object, all of proxy connection should under spipe and managed by spipe object
// it can have only one spipe connection between proxy client and one server at one time
type Spipe struct {
	// remote server connection
	remoteAddr net.Addr
	remoteConn *net.Conn
	localConn  map[uint32]*net.Conn
	activity   bool
	shutdown   bool
	isServer   bool
	isAuth     bool
}

var spipes []*Spipe

// NewSpipe create new spipe object
func NewSpipe(remoteConn *net.Conn, isServer bool) error {
	if !isServer && len(spipes) > 0 {
		return errors.New("Client cannot create more than one spipe")
	}
	if remoteConn == nil {
		return errors.New("Connection is nil")
	}
	spipe := &Spipe{
		remoteAddr: (*remoteConn).RemoteAddr(),
		remoteConn: remoteConn,
		isServer:   isServer,
		localConn:  make(map[uint32]*net.Conn),
		activity:   true,
		shutdown:   false,
		isAuth:     false,
	}
	spipes = append(spipes, spipe)
	spipe.service()
	return nil
}

// SettingRequestHeader  Spipe setting request header
type SettingRequestHeader struct {
	Version  byte
	DataSize uint16
	CMD      byte
	_        uint32
}

// ForwardDataHeader forward data package header
type ForwardDataHeader struct {
	DataSize uint16
	TunnelID uint32
	_        uint16
}

func (spipe *Spipe) service() {
	headerBuffer := make([]byte, 8)
	// forward data buffer default is 4kb
	// TODO: Make the value variable
	forwardDataBuffer := make([]byte, 4*1024)
	var readerBuffer []byte
	buffer := bytes.NewBuffer(readerBuffer)
	go func() {
		for !spipe.shutdown && spipe.remoteConn != nil {
			if _, err := io.ReadFull(*spipe.remoteConn, headerBuffer); err != nil {
				logrus.Warnf("Read full header catch error")
				logrus.WithError(err).Debugf("Spipe is %+v", spipe)
			}
			buffer.Reset()
			buffer.Write(headerBuffer)
			if headerBuffer[7]&1 == 1 {
				// cmd package
				header := &SettingRequestHeader{}
				binary.Read(buffer, binary.BigEndian, header)
			} else {
				// data package
				header := &ForwardDataHeader{}
				binary.Read(buffer, binary.BigEndian, header)
				tunnelID := header.TunnelID
				logrus.WithField("Tunnel ID", tunnelID).Debug("Receive data request with tunnel ID")
				conn, exist := spipe.localConn[tunnelID]
				if !exist || conn == nil {
					logrus.WithField("Tunnel ID", tunnelID).Warn("Not found specific connection")
				}
				remaining := header.DataSize
				for {
					readedByte, err := (*spipe.remoteConn).Read(forwardDataBuffer)
					(*conn).Write(forwardDataBuffer[:readedByte])
					remaining -= uint16(readedByte)
					if remaining == 0 || err != nil {
						// read stream timeout or eof
						break
					}
				}
				if remaining != 0 {
					// data not complete
					logrus.WithField("remaining data size", remaining).Error("Forward data not complete")
				}
			}
		}
	}()
}
