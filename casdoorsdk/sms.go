// Copyright 2023 The Casdoor Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package casdoorsdk

import "encoding/json"

type smsForm struct {
	Content   string   `json:"content"`
	Receivers []string `json:"receivers"`
}

type VerifyCodeForm struct {
	Organization string `json:"organization"`
	Username     string `json:"username"`
	Code         string `json:"code"`
}

func (c *Client) SendSms(content string, receivers ...string) error {
	form := smsForm{
		Content:   content,
		Receivers: receivers,
	}
	postBytes, err := json.Marshal(form)
	if err != nil {
		return err
	}

	_, err = c.DoPost("send-sms", nil, postBytes, false, false)
	if err != nil {
		return err
	}
	return nil
}

func (c *Client) VerifyCode(org string, username string, code string) error {
	form := VerifyCodeForm{
		Organization: org,
		Username:     username,
		Code:         code,
	}
	postBytes, err := json.Marshal(form)
	if err != nil {
		return err
	}

	_, err = c.DoPost("verify-code", nil, postBytes, false, false)
	if err != nil {
		return err
	}
	return nil
}
