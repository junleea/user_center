package worker

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"user_center/proto"
)

func GetGiteeAccessTokenByCode(code string, redirectURI string, clientID string, clientSecret string) (proto.GiteeOAuthTokenResponse, error) {
	req := proto.GiteeOAuthRequest{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Code:         code,
		RedirectURI:  redirectURI,
		GrantType:    "authorization_code",
	}
	var resp proto.GiteeOAuthTokenResponse
	reqBytes, err := json.Marshal(req)
	if err != nil {
		return resp, err
	}
	url := "https://gitee.com/oauth/token"

	err2, respBytes := DoPostRequestJSON(url, reqBytes, nil)
	if err2 != nil {
		return resp, err2
	}
	err = json.Unmarshal(respBytes, &resp)
	if err != nil {
		return resp, err
	}
	return resp, nil
}

func GetGiteeUserInfo(accessToken string) (proto.GitHubUserInfo, error) {
	url := "https://gitee.com/api/v5/user?access_token=" + accessToken
	var resp proto.GitHubUserInfo
	err2, respBytes := DoGetRequest(url, nil)
	if err2 != nil {
		return resp, err2
	}
	err := json.Unmarshal(respBytes, &resp)
	if err != nil {
		return resp, err
	}
	return resp, nil

}

func ExchangeCodeForAccessTokenGithub(clientID, clientSecret, code, redirectURI string) (proto.GitHubOAuthResponse, error) {
	request := proto.GitHubOAuthRequest{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Code:         code,
		RedirectURI:  redirectURI,
	}
	var githubOAuthResponse proto.GitHubOAuthResponse

	var onlineReq proto.OnlineServerReq
	onlineReq.Type = "post"
	onlineReq.PostType = "json"
	onlineReq.Url = "https://github.com/login/oauth/access_token"
	onlineReq.Data = request

	header := make([]proto.OutlineServerReqData, 0)
	header = append(header, proto.OutlineServerReqData{
		Key:   "Content-Type",
		Value: "application/json",
	})
	header = append(header, proto.OutlineServerReqData{
		Key:   "Accept",
		Value: "application/json",
	})
	superTokens := GetRedisSetMembers("super_permission_tokens")
	header = append(header, proto.OutlineServerReqData{
		Key:   "token",
		Value: superTokens[0],
	})
	onlineReq.Header = header
	onlineReqBytes, _ := json.Marshal(onlineReq)
	headers := map[string]string{
		"token":    superTokens[0],
		"super_id": "1",
	}
	log.Println("ExchangeCodeForAccessTokenGithub onlineReqBytes:", string(onlineReqBytes))

	err, respBytes := DoPostRequestJSON("https://vis.ljsea.top/tool/online_server_request?super_id=1", onlineReqBytes, headers)
	if err != nil {
		return githubOAuthResponse, err
	}
	log.Println("ExchangeCodeForAccessTokenGithub respBytes:", string(respBytes))
	var onlineResp proto.OutlineServerReqResp
	err = json.Unmarshal(respBytes, &onlineResp)
	if err != nil {
		return githubOAuthResponse, err
	}
	err = json.Unmarshal([]byte(onlineResp.Data.Response.Response), &githubOAuthResponse)
	if err != nil {
		return githubOAuthResponse, err
	}
	return githubOAuthResponse, nil
}

// 获取用户信息
func GetGitHubUserInfo(accessToken string) (proto.GitHubUserInfo, error) {

	url := "https://api.github.com/user"
	headers := map[string]string{
		"Authorization": "Bearer " + accessToken,
	}
	err, data := DoGetRequest(url, headers)
	var resp proto.GitHubUserInfo
	if err != nil {
		return resp, err
	}
	err = json.Unmarshal(data, &resp)
	if err != nil {
		return resp, err
	}
	if resp.UserID == 0 {
		return resp, errors.New("获取用户信息失败,请检查access_token是否正确")
	}
	return resp, err
}
func GetGitHubUserInfoV2(accessToken string) (proto.GitHubUserInfo, error) {
	url := "https://api.github.com/user"
	var onlineReq proto.OnlineServerReq
	onlineReq.Type = "get"
	onlineReq.Url = url

	header := make([]proto.OutlineServerReqData, 0)
	header = append(header, proto.OutlineServerReqData{
		Key:   "Authorization",
		Value: "Bearer " + accessToken,
	})
	onlineReq.Header = header
	superTokens := GetRedisSetMembers("super_permission_tokens")
	onlineReqBytes, _ := json.Marshal(onlineReq)
	headers := map[string]string{
		"token":    superTokens[0],
		"super_id": "1",
	}
	log.Println("GetGitHubUserInfoV2 onlineReqBytes:", string(onlineReqBytes))
	err, respBytes := DoPostRequestJSON("https://vis.ljsea.top/tool/online_server_request?super_id=1", onlineReqBytes, headers)
	log.Println("GetGitHubUserInfoV2 respBytes:", string(respBytes))
	var onlineResp proto.OutlineServerReqResp
	var resp proto.GitHubUserInfo
	err = json.Unmarshal(respBytes, &onlineResp)
	if err != nil {
		return resp, err
	}
	err = json.Unmarshal([]byte(onlineResp.Data.Response.Response), &resp)
	//err, data := DoGetRequest(url, headers)
	if err != nil {
		return resp, err
	}
	if resp.UserID == 0 {
		return resp, errors.New("获取用户信息失败,请检查access_token是否正确")
	}
	return resp, err
}

// 谷歌登录授权
const (
	GoogleClientID = "194888366727-2uvqs43mimk46mmilc04pptrjkqfjn97.apps.googleusercontent.com"
)

func GetGoogleAccessTokenByCode(code string, redirectURI string, clientID string, clientSecret string) (proto.GoogleOAuthResponse, error) {
	var resp proto.GoogleOAuthResponse

	url := "https://www.googleapis.com/oauth2/v4/token"
	req := proto.GoogleOAuthRequest{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Code:         code,
		RedirectURI:  redirectURI,
		GrantType:    "authorization_code",
	}
	var onlineReq proto.OnlineServerReq
	onlineReq.Type = "post"
	onlineReq.PostType = "form"
	onlineReq.Url = url
	superTokens := GetRedisSetMembers("super_permission_tokens")
	onlineReq.Data = req
	onlineReqBytes, _ := json.Marshal(onlineReq)
	headers := map[string]string{
		"token":    superTokens[0],
		"super_id": "1",
	}

	log.Println("GetGoogleAccessTokenByCode onlineReqBytes:", string(onlineReqBytes))
	err, respBytes := DoPostRequestJSON("https://vis.ljsea.top/tool/online_server_request?super_id=1", onlineReqBytes, headers)
	log.Println("GetGoogleAccessTokenByCode respBytes:", string(respBytes))
	var onlineResp proto.OutlineServerReqResp
	err = json.Unmarshal(respBytes, &onlineResp)
	if err != nil {
		return resp, err
	}
	err = json.Unmarshal([]byte(onlineResp.Data.Response.Response), &resp)
	if err != nil {
		return resp, err
	}
	return resp, nil

}

func GetGoogleUserInfo(accessToken string) (proto.GoogleUserInfoResp, error) {
	var resp proto.GoogleUserInfoResp
	url := "https://www.googleapis.com/oauth2/v2/userinfo?access_token=" + accessToken
	var onlineReq proto.OnlineServerReq
	onlineReq.Type = "get"
	onlineReq.Url = url
	superTokens := GetRedisSetMembers("super_permission_tokens")
	onlineReqBytes, _ := json.Marshal(onlineReq)
	headers := map[string]string{
		"token":    superTokens[0],
		"super_id": "1",
	}
	log.Println("GetGoogleUserInfo onlineReqBytes:", string(onlineReqBytes))
	err, respBytes := DoPostRequestJSON("https://vis.ljsea.top/tool/online_server_request?super_id=1", onlineReqBytes, headers)
	log.Println("GetGoogleUserInfo respBytes:", string(respBytes))
	var onlineResp proto.OutlineServerReqResp
	err = json.Unmarshal(respBytes, &onlineResp)
	if err != nil {
		return resp, err
	}
	err = json.Unmarshal([]byte(onlineResp.Data.Response.Response), &resp)
	//err, respBytes := DoGetRequest(url, nil)
	//if err != nil {
	//	return resp, err
	//}
	err = json.Unmarshal(respBytes, &resp)
	if err != nil {
		return resp, err
	}
	return resp, nil
}

// facebook
const (
	FacebookClientID = "1171721801397908"
)

func GetFacebookAccessTokenByCode(code string, redirectURI string, clientID string, clientSecret string) (proto.FacebookOAuthResponse, error) {
	var resp proto.FacebookOAuthResponse

	url := "https://graph.facebook.com/v22.0/oauth/access_token" + "?client_id=" + clientID + "&client_secret=" + clientSecret + "&code=" + code + "&redirect_uri=" + redirectURI
	//req := proto.FaceBookOAuthRequest{
	//	ClientID:     clientID,
	//	ClientSecret: clientSecret,
	//	Code:         code,
	//	RedirectURI:  redirectURI,
	//}
	log.Println("GetFacebookAccessTokenByCode url:", url)
	var onlineReq proto.OnlineServerReq
	onlineReq.Type = "get"
	onlineReq.Url = url
	superTokens := GetRedisSetMembers("super_permission_tokens")
	//onlineReq.Data = req
	onlineReqBytes, _ := json.Marshal(onlineReq)
	headers := map[string]string{
		"token":    superTokens[0],
		"super_id": "1",
	}

	log.Println("GetFacebookAccessTokenByCode onlineReqBytes:", string(onlineReqBytes))
	err, respBytes := DoPostRequestJSON("https://vis.ljsea.top/tool/online_server_request?super_id=1", onlineReqBytes, headers)
	log.Println("GetFacebookAccessTokenByCode respBytes:", string(respBytes))
	var onlineResp proto.OutlineServerReqResp
	err = json.Unmarshal(respBytes, &onlineResp)
	if err != nil {
		return resp, err
	}
	err = json.Unmarshal([]byte(onlineResp.Data.Response.Response), &resp)
	if err != nil {
		return resp, err
	}
	return resp, nil

}

func GetFaceBookUserInfo(accessToken string) (proto.FaceBookUserInfoResp, error) {
	var resp proto.FaceBookUserInfoResp
	url := "https://graph.facebook.com/v22.0/me?fields=id,name"
	var onlineReq proto.OnlineServerReq
	onlineReq.Type = "get"
	onlineReq.Url = url
	onlineReqHeader := make([]proto.OutlineServerReqData, 0)
	onlineReqHeader = append(onlineReqHeader, proto.OutlineServerReqData{
		Key:   "Authorization",
		Value: "Bearer " + accessToken,
	})
	onlineReq.Header = onlineReqHeader
	superTokens := GetRedisSetMembers("super_permission_tokens")
	onlineReqBytes, _ := json.Marshal(onlineReq)
	headers := map[string]string{
		"token":    superTokens[0],
		"super_id": "1",
	}
	log.Println("GetGoogleUserInfo onlineReqBytes:", string(onlineReqBytes))
	err, respBytes := DoPostRequestJSON("https://vis.ljsea.top/tool/online_server_request?super_id=1", onlineReqBytes, headers)
	log.Println("GetGoogleUserInfo respBytes:", string(respBytes))
	var onlineResp proto.OutlineServerReqResp
	err = json.Unmarshal(respBytes, &onlineResp)
	if err != nil {
		return resp, err
	}
	err = json.Unmarshal([]byte(onlineResp.Data.Response.Response), &resp)
	//err, respBytes := DoGetRequest(url, nil)
	//if err != nil {
	//	return resp, err
	//}
	err = json.Unmarshal(respBytes, &resp)
	if err != nil {
		return resp, err
	}
	return resp, nil
}

const (
	//StackOverflowClientID = "32093"
	//StackOverflowKey      = "rl_s6vbPNPhbFbMcyWp7YbaTeg18" //原始
	StackOverflowClientID = "33284" //新
	StackOverflowKey      = "rl_5g6fVohz3WfVYjsYY1sXqi4Us"
)

func GetStackoverflowAccessTokenByCode(code string, redirectURI string, clientID string, clientSecret string) (proto.StackoverflowOAuthResponse, error) {
	var resp proto.StackoverflowOAuthResponse

	url := "https://stackoverflow.com/oauth/access_token/json"
	req := proto.FaceBookOAuthRequest{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Code:         code,
		RedirectURI:  redirectURI,
	}
	log.Println("GetFacebookAccessTokenByCode url:", url)
	var onlineReq proto.OnlineServerReq
	onlineReq.Type = "post"
	onlineReq.PostType = "form-url-encoded"
	onlineReq.Url = url
	onlineReq.Data = req
	superTokens := GetRedisSetMembers("super_permission_tokens")
	//onlineReq.Data = req
	onlineReqBytes, _ := json.Marshal(onlineReq)
	headers := map[string]string{
		"token":    superTokens[0],
		"super_id": "1",
	}

	log.Println("GetStackoverflowAccessTokenByCode onlineReqBytes:", string(onlineReqBytes))
	err, respBytes := DoPostRequestJSON("https://vis.ljsea.top/tool/online_server_request?super_id=1", onlineReqBytes, headers)
	log.Println("GetStackoverflowAccessTokenByCode respBytes:", string(respBytes))
	var onlineResp proto.OutlineServerReqResp
	err = json.Unmarshal(respBytes, &onlineResp)
	if err != nil {
		return resp, err
	}
	err = json.Unmarshal([]byte(onlineResp.Data.Response.Response), &resp)
	if err != nil {
		return resp, err
	}
	return resp, nil

}

func GetStackoverflowUserInfo(accessToken string) (proto.StackoverflowUserInfoResponse, error) {
	var resp proto.StackoverflowUserInfoResponse
	url := "https://api.stackexchange.com/2.3/me?site=stackoverflow&order=desc&sort=reputation"
	url = fmt.Sprintf("%s&access_token=%s&key=%s", url, accessToken, StackOverflowKey)
	var onlineReq proto.OnlineServerReq
	onlineReq.Type = "get"
	onlineReq.Url = url
	superTokens := GetRedisSetMembers("super_permission_tokens")
	onlineReqBytes, _ := json.Marshal(onlineReq)
	headers := map[string]string{
		"token":    superTokens[0],
		"super_id": "1",
	}
	log.Println("GetStackoverflowUserInfo onlineReqBytes:", string(onlineReqBytes))
	err, respBytes := DoPostRequestJSON("https://vis.ljsea.top/tool/online_server_request?super_id=1", onlineReqBytes, headers)
	log.Println("GetStackoverflowUserInfo respBytes:", string(respBytes))
	var onlineResp proto.OutlineServerReqResp
	err = json.Unmarshal(respBytes, &onlineResp)
	if err != nil {
		return resp, err
	}
	err = json.Unmarshal([]byte(onlineResp.Data.Response.Response), &resp)
	//err, respBytes := DoGetRequest(url, nil)
	//if err != nil {
	//	return resp, err
	//}
	err = json.Unmarshal(respBytes, &resp)
	if err != nil {
		return resp, err
	}
	return resp, nil
}

const (
	QQClientID = "102774740"
)

func GetQQAccessTokenByCode(code string, redirectURI string, clientID string, clientSecret string) (proto.QQOAuthTokenResponse, error) {
	req := proto.QQOAuthRequest{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Code:         code,
		RedirectURI:  redirectURI,
		GrantType:    "authorization_code",
	}
	var resp proto.QQOAuthTokenResponse
	url := "https://graph.qq.com/oauth2.0/token"
	url = fmt.Sprintf("%s?grant_type=%s&client_id=%s&client_secret=%s&code=%s&redirect_uri=%s&fmt=json", url, req.GrantType, req.ClientID, req.ClientSecret, req.Code, req.RedirectURI)

	err2, respBytes := DoGetRequest(url, nil)
	if err2 != nil {
		return resp, err2
	}
	err := json.Unmarshal(respBytes, &resp)
	if err != nil {
		return resp, err
	}
	return resp, nil
}

func GetQQUserInfo(accessToken string) (proto.QQUserInfoResponse, error) {
	var resp proto.QQUserInfoResponse

	var openIDInfo proto.GetQQOpenIDResponse
	//先获取openid
	url := fmt.Sprintf("https://graph.qq.com/oauth2.0/me?access_token=%s&fmt=json", accessToken)
	err2, respBytes := DoGetRequest(url, nil)
	if err2 != nil {
		log.Println("GetQQUserInfo get openid err:", err2)
		return resp, err2
	}
	err := json.Unmarshal(respBytes, &openIDInfo)
	if err != nil {
		return resp, err
	}

	//如果openid获取成功，获取用户信息
	url = fmt.Sprintf("https://graph.qq.com/user/get_user_info?access_token=%s&oauth_consumer_key=%s&openid=%s&fmt=json", accessToken, QQClientID, openIDInfo.OpenID)
	err3, respBytes2 := DoGetRequest(url, nil)
	if err3 != nil {
		log.Println("GetQQUserInfo get user info err:", err2)
		return resp, err2
	}
	err = json.Unmarshal(respBytes2, &resp)
	if err != nil {
		return resp, err
	}
	resp.OpenID = openIDInfo.OpenID
	return resp, nil

}

// 我的自部署gitea
const (
	MyGiteaClientID = "812f4f39-8b98-426e-a542-3115ff4fb2be"

	//官方版本
	GiteaClientID = "035b79b8-ba9a-4c4b-bb41-ede796d168c8"
)

// 由于gitea有自部署与官方区别，
func GetGiteaAccessTokenByCode(baseUrl, code string, redirectURI string, clientID string, clientSecret string) (proto.GiteaOAuthResponse, error) {
	var resp proto.GiteaOAuthResponse

	url := baseUrl + "/login/oauth/access_token"
	req := proto.GiteaOAuthRequest{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Code:         code,
		RedirectURI:  redirectURI,
		GrantType:    "authorization_code",
	}
	reqData, err := json.Marshal(req)

	log.Println("gitea request url:", url, "reqData:", string(reqData))
	err2, respBytes := DoPostRequestJSON(url, reqData, nil)
	if err2 != nil {
		log.Println("gitea response err:", err2)
		return resp, err2
	}
	err = json.Unmarshal(respBytes, &resp)
	if err != nil {
		log.Println("gitea response decode err:", err, " response content:", string(respBytes))
		return resp, err
	}
	return resp, nil
}

func GetGiteaUserInfo(baseDomain, accessToken string) (proto.GiteaUserInfo, error) {
	url := baseDomain + "/login/oauth/userinfo"
	headers := map[string]string{
		"Authorization": "bearer " + accessToken,
	}
	var resp proto.GiteaUserInfo
	err2, respBytes := DoGetRequest(url, headers)
	if err2 != nil {
		return resp, err2
	}
	err := json.Unmarshal(respBytes, &resp)
	if err != nil {
		return resp, err
	}
	return resp, nil

}

// microsoft登录
const (
	MicroSoftClientID = "53ce40d3-260e-4256-a500-201b30203e80"
	MicroSoftTenantID = "df0fa05b-820a-48c3-8ebd-f159845bf0b2"
)

func GetMicroSoftAccessTokenByCode(code string, redirectURI string, clientID string, clientSecret string) (proto.MicrosoftOAuthResponse, error) {
	var resp proto.MicrosoftOAuthResponse

	url := fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", MicroSoftTenantID)
	req := proto.MicrosoftOAuthRequest{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Code:         code,
		RedirectURI:  redirectURI,
		GrantType:    "authorization_code",
	}
	reqData, err := json.Marshal(req)

	log.Println("microsoft request url:", url, "reqData:", string(reqData))
	err2, respBytes := DoPostRequestFormUrlEncoded(url, reqData, nil)
	if err2 != nil {
		log.Println("microsoft response err:", err2)
		return resp, err2
	}
	log.Println("microsoft response content:", string(respBytes))
	err = json.Unmarshal(respBytes, &resp)
	if err != nil {
		log.Println("microsoft response decode err:", err, " response content:", string(respBytes))
		return resp, err
	}
	return resp, nil
}

func GetMicroSoftUserInfo(accessToken string) (proto.MicrosoftUserInfo, error) {
	url := "https://graph.microsoft.com/v1.0/me"
	headers := map[string]string{
		"Authorization": "Bearer " + accessToken,
	}
	var resp proto.MicrosoftUserInfo
	err2, respBytes := DoGetRequest(url, headers)
	if err2 != nil {
		return resp, err2
	}
	err := json.Unmarshal(respBytes, &resp)
	if err != nil {
		return resp, err
	}
	return resp, nil
}
