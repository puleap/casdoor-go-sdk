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

import (
	"testing"
)

func TestSendVerificationCode(t *testing.T) {
	InitConfig(TestCasdoorEndpoint, TestClientId, TestClientSecret, TestJwtPublicKey, TestCasdoorOrganization, TestCasdoorApplication)

	form := VerificationForm{
		Dest:          "15912341234",
		Type:          "phone",
		CountryCode:   "",
		ApplicationId: TestCasdoorApplication,
		Method:        "login",
		CheckUser:     "",

		CaptchaType:  "none",
		ClientSecret: "",
		CaptchaToken: "",
	}

	err := SendVerificationCode(form)
	if err != nil {
		t.Fatalf("Failed to get code: %v", err)
	}
}

func TestLogin(t *testing.T) {
	InitConfig(TestCasdoorEndpoint, TestClientId, TestClientSecret, TestJwtPublicKey, TestCasdoorOrganization, TestCasdoorApplication)

	form := AuthForm{
		Organization: TestCasdoorOrganization,
		Application:  TestCasdoorApplication,
		AutoSignin:   false,
		Type:         "token",
		// SigninMethod: "Verification code",
		SigninMethod: "Password",
		Username:     "15912341234",
		// Code:         "",
		Password: "123456",
	}

	token, err := Login(form)
	if err != nil {
		t.Fatalf("Failed to login: %v", err)
	}

	t.Logf("login success: %s", token)
}
