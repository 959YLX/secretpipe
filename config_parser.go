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
	"io/ioutil"

	"github.com/959YLX/secretpipe/service"

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
				Timeout    int    `yaml:timeout`
			}
			Users []struct {
				UserName string `yaml:username`
				Password string `yaml:password`
			}
		}
	}
}

// PipeConfig 配置信息对象
var config *Config

// LoadConfig 加载配置信息
func LoadConfig() error {
	config = &Config{}
	buffer, err := ioutil.ReadFile("config.yaml")
	if err != nil {
		logrus.WithError(err).Error("Load config file error")
		return err
	}
	if err = yaml.Unmarshal(buffer, config); err != nil {
		logrus.WithError(err).Error("Parse config file error")
		return err
	}
	for _, user := range config.Pipe.Server.Users {
		service.PutUser(user.UserName, user.Password)
	}
	return nil
}
