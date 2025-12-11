package handler

import (
	"github.com/gin-gonic/gin"
	"net/http"
	"user_center/proto"
	"user_center/service"
)

func SetUpMyVPNGroup(router *gin.Engine) {
	myVPNGroup := router.Group("/vpn")
	myVPNGroup.POST("/server_register", ServerRegisterHandler)
	myVPNGroup.GET("/get_support_vpn_server", GetSupportVPNServerHandler)
	myVPNGroup.GET("/get_client_config", GetClientConfigHandler)
	myVPNGroup.GET("/get_server_config", GetServerConfigHandler)
	myVPNGroup.PUT("/client_heartbeat", ClientHeartbeatHandler)
	myVPNGroup.GET("/get_vpn_user", GetVPNUserHandler)
	myVPNGroup.POST("/set_vpn_server_config", SetVPNServerConfigHandler)
	myVPNGroup.GET("/get_vpn_server_config", GetVPNServerConfigHandler)
	myVPNGroup.DELETE("/delete_vpn_server", DeleteVPNServerHandler)
	myVPNGroup.POST("/set_vpn_ip_pool", SetVPNPoolHandler)
	myVPNGroup.DELETE("/delete_vpn_ip_pool", DeleteVPNPoolHandler)
	myVPNGroup.POST("/set_vpn_tunnel", SetVPNTunnelHandler)
	myVPNGroup.DELETE("/delete_vpn_tunnel", DeleteVPNTunnelHandler)
}

func SetVPNTunnelHandler(c *gin.Context) {
	var resp proto.GenerateResp
	requestID, _ := c.Get("request_id")
	resp.RequestID = requestID.(string)

	c.JSON(http.StatusOK, resp)
}

func DeleteVPNTunnelHandler(c *gin.Context) {
	var resp proto.GenerateResp
	requestID, _ := c.Get("request_id")
	resp.RequestID = requestID.(string)

	c.JSON(http.StatusOK, resp)
}

func GetClientConfigHandler(c *gin.Context) {
	var resp proto.GenerateResp
	requestID, _ := c.Get("request_id")
	resp.RequestID = requestID.(string)

	c.JSON(http.StatusOK, resp)
}

func GetSupportVPNServerHandler(c *gin.Context) {
	var resp proto.GenerateResp
	requestID, _ := c.Get("request_id")
	resp.RequestID = requestID.(string)

	c.JSON(http.StatusOK, resp)
}

func ServerRegisterHandler(c *gin.Context) {
	user := RequestGetUserInfo(c)
	var resp proto.GenerateResp
	requestID, _ := c.Get("request_id")
	resp.RequestID = requestID.(string)
	var req proto.SetServerConfigRequest
	if err := c.ShouldBind(&req); err != nil {
		resp.Code = proto.ParameterError
		resp.Message = "invalid parameter: " + err.Error()
	} else {
		resp.Code, err = service.RegisterMyVPNServerConfigService(&user, &req)
		resp.Message = err.Error()
	}

	c.JSON(http.StatusOK, resp)
}

func GetServerConfigHandler(c *gin.Context) {
	var resp proto.GenerateResp
	requestID, _ := c.Get("request_id")
	resp.RequestID = requestID.(string)

	c.JSON(http.StatusOK, resp)
}

func ClientHeartbeatHandler(c *gin.Context) {
	var resp proto.GenerateResp
	requestID, _ := c.Get("request_id")
	resp.RequestID = requestID.(string)

	c.JSON(http.StatusOK, resp)
}

func GetVPNUserHandler(c *gin.Context) {
	var resp proto.GenerateResp
	requestID, _ := c.Get("request_id")
	resp.RequestID = requestID.(string)

	c.JSON(http.StatusOK, resp)
}

func SetVPNServerConfigHandler(c *gin.Context) {
	user := RequestGetUserInfo(c)
	var resp proto.GenerateResp
	requestID, _ := c.Get("request_id")
	resp.RequestID = requestID.(string)
	var req proto.SetServerConfigRequest
	if err := c.ShouldBind(&req); err != nil {
		resp.Code = proto.ParameterError
		resp.Message = "invalid parameter: " + err.Error()
	} else {
		resp.Code, err = service.SetMyVPNServerConfigService(&user, &req)
		if err != nil {
			resp.Message = err.Error()
		}
	}
	c.JSON(http.StatusOK, resp)
}

func DeleteVPNServerHandler(c *gin.Context) {
	user := RequestGetUserInfo(c)
	var resp proto.GenerateResp
	requestID, _ := c.Get("request_id")
	resp.RequestID = requestID.(string)
	var req proto.SetServerConfigRequest
	if err := c.ShouldBind(&req); err != nil {
		resp.Code = proto.ParameterError
		resp.Message = "invalid parameter: " + err.Error()
	} else {
		resp.Code, err = service.DeleteMyVPNServerConfigService(&user, &req)
		if err != nil {
			resp.Message = err.Error()
		}
	}

	c.JSON(http.StatusOK, resp)
}

func GetVPNServerConfigHandler(c *gin.Context) {
	user := RequestGetUserInfo(c)
	var resp proto.GenerateResp
	requestID, _ := c.Get("request_id")
	resp.RequestID = requestID.(string)

	var err error
	resp.Code, resp.Data, err = service.GetMyVPNServerConfigService(&user)
	if err != nil {
		resp.Message = err.Error()
	}
	resp.Message = "success"

	c.JSON(http.StatusOK, resp)
}

func SetVPNPoolHandler(c *gin.Context) {
	var resp proto.GenerateResp
	requestID, _ := c.Get("request_id")
	resp.RequestID = requestID.(string)

	c.JSON(http.StatusOK, resp)
}

func DeleteVPNPoolHandler(c *gin.Context) {
	var resp proto.GenerateResp
	requestID, _ := c.Get("request_id")
	resp.RequestID = requestID.(string)

	c.JSON(http.StatusOK, resp)
}
