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
	"math/rand"
	"net"
	"sync"
	"time"

	"github.com/959YLX/secretpipe/util"

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
	remoteAddr    *net.Addr
	remoteConn    *net.Conn
	localConn     map[uint32]*net.Conn
	activity      bool
	isServer      bool
	isAuth        bool
	encryptor     func(data []byte, key []byte) []byte
	decryptor     func(data []byte, key []byte) []byte
	key           []byte
	offlineTime   time.Time
	spipeID       uint32
	randGenerator *rand.Rand
}

var existSpipes map[uint32]*Spipe
var spipeMapMutex = new(sync.Mutex)

// NewSpipe create new spipe object
func NewSpipe(remoteConn *net.Conn, isServer bool) error {
	if !isServer && len(existSpipes) > 0 {
		return errors.New("Client cannot create more than one spipe")
	}
	if remoteConn == nil {
		return errors.New("Connection is nil")
	}
	remoteAddr := (*remoteConn).RemoteAddr()
	generator := rand.New(rand.NewSource(time.Now().Unix()))
	spipe := &Spipe{
		remoteAddr:    &remoteAddr,
		remoteConn:    remoteConn,
		isServer:      isServer,
		localConn:     make(map[uint32]*net.Conn),
		activity:      true,
		isAuth:        false,
		randGenerator: generator,
	}
	spipe.generateSpipeID()
	spipe.service()
	return nil
}

func (spipe *Spipe) activityRecover(recoverData []byte) error {
	return nil
}

// SettingRequestHeader  Spipe setting request header
type SettingRequestHeader struct {
	Version  byte
	DataSize uint16
	CMD      byte
	_        uint32
}

// SettingResponseHeader Spipe setting response header
type SettingResponseHeader struct {
	Success  bool
	DataSize uint16
	CMD      byte
	_        uint32
}

// SettingErrorResponseData setting error data
type SettingErrorResponseData struct {
	ErrorCode uint16
	Msg       string
}

func (data *SettingErrorResponseData) toBytes() *[]byte {
	msgLen := len(data.Msg)
	bufferBytes := make([]byte, 4+msgLen)
	buffer := bytes.NewBuffer(bufferBytes)
	binary.Write(buffer, binary.BigEndian, data.ErrorCode)
	binary.Write(buffer, binary.BigEndian, uint16(msgLen))
	buffer.Write([]byte(data.Msg))
	retBytes := buffer.Bytes()
	return &retBytes
}

// ForwardDataHeader forward data package header
type ForwardDataHeader struct {
	DataSize uint16
	TunnelID uint32
	_        uint16
}

const (
	authCMD byte = 0x01
)

const (
	cmdNotFoundErrorCode uint16 = 0x0001
	cmdNotFoundErrorMsg  string = "Request CMD not found"
	authErrorCode        uint16 = 0x0002
	authNotPassErrorMsg  string = "Wrong user name or password"
)

var (
	// ErrIncompleteData incomplete cmd data
	ErrIncompleteData = errors.New("incomplete cmd data")
)

// AuthRequestData 认证请求数据
type AuthRequestData struct {
	UName  string
	Passwd string
}

func authParser(data []byte) (*AuthRequestData, error) {
	totalSize := len(data)
	if totalSize < 2 {
		return nil, ErrIncompleteData
	}
	unameSize := data[0]
	pwdSize := data[1]
	if totalSize < int(unameSize+pwdSize+2) {
		return nil, ErrIncompleteData
	}
	unameBytes := data[2 : 2+unameSize]
	pwdBytes := data[2+unameSize : 2+unameSize+pwdSize]
	return &AuthRequestData{UName: string(unameBytes), Passwd: string(pwdBytes)}, nil
}

func (spipe *Spipe) service() {
	headerBuffer := make([]byte, 8)
	// forward data buffer default is 4kb
	// TODO: Make the value variable
	forwardDataBuffer := make([]byte, 4*1024)
	var readerBuffer []byte
	buffer := bytes.NewBuffer(readerBuffer)
	go func() {
		defer func() {
			recover()
			if spipe.remoteConn != nil {
				(*spipe.remoteConn).Close()
				spipe.remoteAddr = nil
				spipe.remoteConn = nil
			}
			spipe.activity = false
			spipe.offlineTime = time.Now()
		}()
		for spipe.activity && spipe.remoteConn != nil {
			if _, err := io.ReadFull(*spipe.remoteConn, headerBuffer); err != nil {
				if err == io.ErrUnexpectedEOF {
					logrus.Warnf("Read full header catch error")
				}
				break
			}
			buffer.Reset()
			buffer.Write(headerBuffer)
			if headerBuffer[7]&1 == 1 {
				// cmd package
				header := &SettingRequestHeader{}
				err := binary.Read(buffer, binary.BigEndian, header)
				if err != nil {
					logrus.WithError(err).Error("Read cmd header error")
					continue
				}
				data := make([]byte, header.DataSize)
				if _, err = io.ReadFull(*spipe.remoteConn, data); err != nil {
					logrus.WithError(err).Warn("Receive incomplete data")
					continue
				}
				var retDataPtr *[]byte
				responseHeader := SettingResponseHeader{
					Success: true,
					CMD:     header.CMD,
				}
				switch header.CMD {
				case authCMD:
					authData, err := authParser(data)
					if err != nil {
						retDataPtr = (&SettingErrorResponseData{ErrorCode: authErrorCode, Msg: err.Error()}).toBytes()
						responseHeader.Success = false
					}
					if util.Auth(authData.UName, authData.Passwd) {
						retData := make([]byte, 4)
						binary.BigEndian.PutUint32(retData, spipe.spipeID)
						retDataPtr = &retData
					} else {
						retDataPtr = (&SettingErrorResponseData{ErrorCode: authErrorCode, Msg: authNotPassErrorMsg}).toBytes()
						responseHeader.Success = false
					}
				default:
					retDataPtr = (&SettingErrorResponseData{ErrorCode: cmdNotFoundErrorCode, Msg: cmdNotFoundErrorMsg}).toBytes()
					responseHeader.Success = false
				}
				if retDataPtr == nil {
					responseHeader.DataSize = 0
					binary.Write(*spipe.remoteConn, binary.BigEndian, &responseHeader)
				} else {
					retData := *retDataPtr
					responseHeader.DataSize = uint16(len(retData))
					binary.Write(*spipe.remoteConn, binary.BigEndian, &responseHeader)
					(*spipe.remoteConn).Write(retData)
				}
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
					logrus.WithField("remaining data size", remaining).Error("Incomplete forward data")
				}
			}
		}
	}()
}

func (spipe *Spipe) generateSpipeID() {
	var id uint32
	spipeMapMutex.Lock()
	for {
		id = spipe.randGenerator.Uint32()
		if _, exist := existSpipes[id]; !exist {
			break
		}
	}
	existSpipes[id] = spipe
	spipeMapMutex.Unlock()
	spipe.spipeID = id
}
