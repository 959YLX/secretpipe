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

package util

import (
	"io/ioutil"

	"github.com/sirupsen/logrus"
	yaml "gopkg.in/yaml.v2"
)

// Config 配置信息结构
type Config struct {
	Pipe struct {
		Server struct {
			Listeners []struct {
				Protocol   string `yaml:protocol`
				IP         string `yaml:ip`
				Port       int    `yaml:port`
				Encryption string `yaml:encryption`
			}
			Users []struct {
				UserName string `yaml:username`
				Password string `yaml:password`
			}
		}
	}
}

// PipeConfig 配置信息对象
var PipeConfig *Config
var userMap map[string]string

// LoadConfig 加载配置信息
func LoadConfig() error {
	PipeConfig = &Config{}
	buffer, err := ioutil.ReadFile("config.yaml")
	if err != nil {
		logrus.WithError(err).Error("Load config file error")
		return err
	}
	if err = yaml.Unmarshal(buffer, PipeConfig); err != nil {
		logrus.WithError(err).Error("Parse config file error")
		return err
	}
	userMap = make(map[string]string)
	for _, user := range PipeConfig.Pipe.Server.Users {
		userMap[user.UserName] = user.Password
	}
	return nil
}

// Auth Check user legitimacy
func Auth(username string, password string) bool {
	if configPassword, exist := userMap[username]; exist && configPassword == password {
		return true
	}
	return false
}
