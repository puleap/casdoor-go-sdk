// Copyright 2021 The Casdoor Authors. All Rights Reserved.
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
	"encoding/json"
	"fmt"
)

type ProviderItem struct {
	Owner string `json:"owner"`
	Name  string `json:"name"`

	CanSignUp   bool      `json:"canSignUp"`
	CanSignIn   bool      `json:"canSignIn"`
	CanUnlink   bool      `json:"canUnlink"`
	Prompted    bool      `json:"prompted"`
	SignupGroup string    `json:"signupGroup"`
	Rule        string    `json:"rule"`
	Provider    *Provider `json:"provider"`
}

type SigninMethod struct {
	Name        string `xorm:"varchar(100) notnull pk" json:"name"`
	DisplayName string `xorm:"varchar(100)" json:"displayName"`
	Rule        string `json:"rule"`
}

type SignupItem struct {
	Name        string `json:"name"`
	Visible     bool   `json:"visible"`
	Required    bool   `json:"required"`
	Prompted    bool   `json:"prompted"`
	Label       string `json:"label"`
	Placeholder string `json:"placeholder"`
	Rule        string `json:"rule"`
}

type SamlItem struct {
	Name       string `json:"name"`
	NameFormat string `json:"nameformat"`
	Value      string `json:"value"`
}

type Application struct {
	Owner       string `xorm:"varchar(100) notnull pk" json:"owner"`
	Name        string `xorm:"varchar(100) notnull pk" json:"name"`
	CreatedTime string `xorm:"varchar(100)" json:"createdTime"`

	DisplayName         string          `xorm:"varchar(100)" json:"displayName"`
	Logo                string          `xorm:"varchar(200)" json:"logo"`
	HomepageUrl         string          `xorm:"varchar(100)" json:"homepageUrl"`
	Description         string          `xorm:"varchar(100)" json:"description"`
	Organization        string          `xorm:"varchar(100)" json:"organization"`
	Cert                string          `xorm:"varchar(100)" json:"cert"`
	EnablePassword      bool            `json:"enablePassword"`
	EnableSignUp        bool            `json:"enableSignUp"`
	EnableSigninSession bool            `json:"enableSigninSession"`
	EnableAutoSignin    bool            `json:"enableAutoSignin"`
	EnableCodeSignin    bool            `json:"enableCodeSignin"`
	EnableSamlCompress  bool            `json:"enableSamlCompress"`
	EnableSamlC14n10    bool            `json:"enableSamlC14n10"`
	EnableWebAuthn      bool            `json:"enableWebAuthn"`
	EnableLinkWithEmail bool            `json:"enableLinkWithEmail"`
	OrgChoiceMode       string          `json:"orgChoiceMode"`
	SamlReplyUrl        string          `xorm:"varchar(100)" json:"samlReplyUrl"`
	Providers           []*ProviderItem `xorm:"mediumtext" json:"providers"`
	SigninMethods       []*SigninMethod `xorm:"varchar(2000)" json:"signinMethods"`
	SignupItems         []*SignupItem   `xorm:"varchar(2000)" json:"signupItems"`
	GrantTypes          []string        `xorm:"varchar(1000)" json:"grantTypes"`
	OrganizationObj     *Organization   `xorm:"-" json:"organizationObj"`
	CertPublicKey       string          `xorm:"-" json:"certPublicKey"`
	Tags                []string        `xorm:"mediumtext" json:"tags"`
	InvitationCodes     []string        `xorm:"varchar(200)" json:"invitationCodes"`
	SamlAttributes      []*SamlItem     `xorm:"varchar(1000)" json:"samlAttributes"`

	ClientId             string     `xorm:"varchar(100)" json:"clientId"`
	ClientSecret         string     `xorm:"varchar(100)" json:"clientSecret"`
	RedirectUris         []string   `xorm:"varchar(1000)" json:"redirectUris"`
	TokenFormat          string     `xorm:"varchar(100)" json:"tokenFormat"`
	TokenFields          []string   `xorm:"varchar(1000)" json:"tokenFields"`
	ExpireInHours        int        `json:"expireInHours"`
	RefreshExpireInHours int        `json:"refreshExpireInHours"`
	SignupUrl            string     `xorm:"varchar(200)" json:"signupUrl"`
	SigninUrl            string     `xorm:"varchar(200)" json:"signinUrl"`
	ForgetUrl            string     `xorm:"varchar(200)" json:"forgetUrl"`
	AffiliationUrl       string     `xorm:"varchar(100)" json:"affiliationUrl"`
	TermsOfUse           string     `xorm:"varchar(100)" json:"termsOfUse"`
	SignupHtml           string     `xorm:"mediumtext" json:"signupHtml"`
	SigninHtml           string     `xorm:"mediumtext" json:"signinHtml"`
	ThemeData            *ThemeData `xorm:"json" json:"themeData"`
	FormCss              string     `xorm:"text" json:"formCss"`
	FormCssMobile        string     `xorm:"text" json:"formCssMobile"`
	FormOffset           int        `json:"formOffset"`
	FormSideHtml         string     `xorm:"mediumtext" json:"formSideHtml"`
	FormBackgroundUrl    string     `xorm:"varchar(200)" json:"formBackgroundUrl"`

	FailedSigninLimit      int `json:"failedSigninLimit"`
	FailedSigninfrozenTime int `json:"failedSigninfrozenTime"`
}

func (c *Client) GetApplications() ([]*Application, error) {
	queryMap := map[string]string{
		"owner": "admin",
	}

	url := c.GetUrl("get-applications", queryMap)

	bytes, err := c.DoGetBytes(url)
	if err != nil {
		return nil, err
	}

	var applications []*Application
	err = json.Unmarshal(bytes, &applications)
	if err != nil {
		return nil, err
	}
	return applications, nil
}

func (c *Client) GetOrganizationApplications() ([]*Application, error) {
	queryMap := map[string]string{
		"owner":        "admin",
		"organization": c.OrganizationName,
	}

	url := c.GetUrl("get-organization-applications", queryMap)

	bytes, err := c.DoGetBytes(url)
	if err != nil {
		return nil, err
	}

	var applications []*Application
	err = json.Unmarshal(bytes, &applications)
	if err != nil {
		return nil, err
	}
	return applications, nil
}

func (c *Client) GetApplication(name string) (*Application, error) {
	queryMap := map[string]string{
		"id": fmt.Sprintf("%s/%s", "admin", name),
	}

	url := c.GetUrl("get-application", queryMap)

	bytes, err := c.DoGetBytes(url)
	if err != nil {
		return nil, err
	}

	var application *Application
	err = json.Unmarshal(bytes, &application)
	if err != nil {
		return nil, err
	}
	return application, nil
}

func (c *Client) AddApplication(application *Application) (bool, error) {
	_, affected, err := c.modifyApplication("add-application", application, nil)
	return affected, err
}

func (c *Client) DeleteApplication(application *Application) (bool, error) {
	_, affected, err := c.modifyApplication("delete-application", application, nil)
	return affected, err
}

func (c *Client) UpdateApplication(name string, application *Application) (bool, error) {
	application.Owner = "admin"

	queryMap := map[string]string{
		"id": fmt.Sprintf("%s/%s", application.Owner, name),
	}

	postBytes, err := json.Marshal(application)
	if err != nil {
		return false, err
	}

	resp, err := c.DoPost("update-application", queryMap, postBytes, false, false)
	if err != nil {
		return false, err
	}

	return resp.Data == "Affected", nil

	_, affected, err := c.modifyApplication("update-application", application, nil)
	return affected, err
}
