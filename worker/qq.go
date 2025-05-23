package worker

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
)

const (
	AppId       = "101827468"
	AppKey      = "0d2d856e48e0ebf6b98e0d0c879fe74d"
	RedirectURI = "https://www.ljsea.top/qq_callback.php"
)

type PrivateInfo struct {
	AccessToken  string `json:"access_token"`
	ExpiresIn    string `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	OpenId       string `json:"openid"`
}

//func main() {
//	http.HandleFunc("/toLogin", GetAuthCode)
//	http.HandleFunc("/qqLogin", GetToken)
//
//	fmt.Println("started...")
//	err := http.ListenAndServe(":9090", nil)
//	if err != nil {
//		panic(err)
//	}
//}

type GetCodeResponse struct {
}
type GetCodeRequest struct {
	ResponseType string `json:"response_type"`
	ClientID     string `json:"client_id"`
	RedirectURI  string `json:"redirect_uri"`
	State        string `json:"state"`
	Scope        string `json:"scope,omitempty"`
	Display      string `json:"display,omitempty"`
}

type QQAccessTokenRequest struct {
	GrantType    string `json:"grant_type"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	Code         string `json:"code"`
	RedirectURI  string `json:"redirect_uri"`
	Fmt          string `json:"fmt,omitempty"`
	NeedOpenID   string `json:"need_openid,omitempty"`
}

type QQAccessTokenResponse struct {
	AccessToken  string `json:"access_token"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
}

type QQRefreshTokenRequest struct {
	GrantType    string `json:"grant_type"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	RefreshToken string `json:"refresh_token"`
	Fmt          string `json:"fmt,omitempty"`
}

// 2. Get Access Token
func GetQQToken(code string) string {
	var accessToken string
	params := url.Values{}
	params.Add("grant_type", "authorization_code")
	params.Add("client_id", AppId)
	params.Add("client_secret", AppKey)
	params.Add("code", code)
	str := fmt.Sprintf("%s&redirect_uri=%s", params.Encode(), RedirectURI)
	loginURL := fmt.Sprintf("%s?%s", "https://graph.qq.com/oauth2.0/token", str)

	response, err := http.Get(loginURL)
	if err != nil {
		log.Println("GetQQToken error:", err.Error())
		return accessToken
	}
	defer response.Body.Close()

	bs, _ := io.ReadAll(response.Body)
	body := string(bs)

	resultMap := convertToMap(body)

	info := &PrivateInfo{}
	info.AccessToken = resultMap["access_token"]
	info.RefreshToken = resultMap["refresh_token"]
	info.ExpiresIn = resultMap["expires_in"]
	return info.AccessToken
}

// 3. Get QQ OpenId
func GetOpenId(accessToken string) {
	resp, err := http.Get(fmt.Sprintf("%s?access_token=%s", "https://graph.qq.com/oauth2.0/me", accessToken))
	if err != nil {
		return
	}
	defer resp.Body.Close()

	bs, _ := io.ReadAll(resp.Body)
	body := string(bs)
	openId := body[45:77]

	info, err := GetUserInfo(accessToken, openId)
	if err != nil {
		return
	}
	log.Println(info)
}

// 4. Get User info
func GetUserInfo(accessToken string, openID string) (string, error) {
	params := url.Values{}
	params.Add("access_token", accessToken)
	params.Add("openid", openID)
	params.Add("oauth_consumer_key", AppId)

	uri := fmt.Sprintf("https://graph.qq.com/user/get_user_info?%s", params.Encode())
	resp, err := http.Get(uri)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	bs, _ := io.ReadAll(resp.Body)
	return string(bs), nil
}

func convertToMap(str string) map[string]string {
	var resultMap = make(map[string]string)
	values := strings.Split(str, "&")
	for _, value := range values {
		vs := strings.Split(value, "=")
		resultMap[vs[0]] = vs[1]
	}
	return resultMap
}
