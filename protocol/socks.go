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

// Socks5CheckRequest socks5效验请求
type Socks5CheckRequest struct {
	VER      byte
	NMETHODS byte
	METHODS  []byte
}

// Socks5CheckResponse socks5效验回复
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

// Socks5DataRequest socks5数据请求
type Socks5DataRequest struct {
	VER  byte
	CMD  byte
	RSV  byte
	ATYP byte
	DST  []byte
}

// Socks5DataResponse socks5数据响应
type Socks5DataResponse struct {
	VER  byte
	REP  byte
	RSV  byte
	ATYP byte
	BND  []byte
}
