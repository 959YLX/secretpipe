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

// Auth Service

package service

import "sync"

var authService *AuthService

func init() {
	authService = &AuthService{}
}

// AuthService auth service
type AuthService struct {
	usersMap sync.Map
}

// PutUser put user to auth service
func PutUser(username string, password string) {
	authService.usersMap.Store(username, password)
}

// Auth Check user legitimacy
func Auth(username string, password string) bool {
	if psw, exist := authService.usersMap.Load(username); exist {
		if storagePassword, ok := psw.(string); ok {
			return password == storagePassword
		}
	}
	return false
}
