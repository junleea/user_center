package handler

import (
	"github.com/gin-gonic/gin"
	"log"
	"net/http"
	"user_center/proto"
	"user_center/service"
)

func SetUpMyVPNGroup(router *gin.Engine) {
	myVPNGroup := router.Group("/vpn")
	myVPNGroup.POST("/server_register", ServerRegisterHandler)
	myVPNGroup.GET("/get_support_vpn_server", GetSupportVPNServerHandler)
	myVPNGroup.POST("/update_client_status", UpdateClientStatusHandler)
	myVPNGroup.POST("/update_server_status", UpdateServerStatusHandler)
	myVPNGroup.GET("/get_client_config", GetClientConfigHandler) //prepare online
	myVPNGroup.GET("/get_server_config", GetServerConfigHandler)
	myVPNGroup.PUT("/client_heartbeat", ClientHeartbeatHandler)
	myVPNGroup.GET("/get_vpn_user", GetVPNUserHandler)
	myVPNGroup.POST("/set_vpn_server_config", SetVPNServerConfigHandler)
	myVPNGroup.GET("/get_vpn_server_config", GetVPNServerConfigHandler)
	myVPNGroup.GET("/get_server_online", GetVPNServerOnlineListHandler)
	myVPNGroup.DELETE("/delete_vpn_server", DeleteVPNServerHandler)
	myVPNGroup.POST("/set_vpn_ip_pool", SetVPNPoolHandler)
	myVPNGroup.GET("/get_vpn_ip_pool", GetVPNAddressPoolHandler)
	myVPNGroup.DELETE("/delete_vpn_ip_pool", DeleteVPNPoolHandler)
	myVPNGroup.POST("/set_vpn_tunnel", SetVPNTunnelHandler)
	myVPNGroup.DELETE("/delete_vpn_tunnel", DeleteVPNTunnelHandler)
	myVPNGroup.GET("/get_vpn_tunnel_config", GetVPNTunnelConfigHandler)
}

func UpdateServerStatusHandler(c *gin.Context) {
	user := RequestGetUserInfo(c)
	var resp proto.GenerateResp
	requestID, _ := c.Get("request_id")
	resp.RequestID = requestID.(string)
	var req proto.SetVPNServerStatusReq
	if err := c.ShouldBind(&req); err != nil {
		resp.Code = proto.ParameterError
		resp.Message = "invalid parameter: " + err.Error()
	} else {
		service.SetServerStatusService(&user, &req, &resp)
	}
	c.JSON(http.StatusOK, resp)
}

func UpdateClientStatusHandler(c *gin.Context) {
	user := RequestGetUserInfo(c)
	var resp proto.GenerateResp
	requestID, _ := c.Get("request_id")
	resp.RequestID = requestID.(string)
	var req proto.SetVPNClientStatusReq
	if err := c.ShouldBind(&req); err != nil {
		resp.Code = proto.ParameterError
		resp.Message = "invalid parameter: " + err.Error()
	} else {
		service.SetClientStatusService(&user, &req, &resp)
	}
	c.JSON(http.StatusOK, resp)
}

func GetVPNServerOnlineListHandler(c *gin.Context) {
	user := RequestGetUserInfo(c)
	var resp proto.GenerateResp
	serverId := c.Query("server_id")
	requestID, _ := c.Get("request_id")
	resp.RequestID = requestID.(string)
	service.GetVPNServerOnlineList(&user, serverId, &resp)
	c.JSON(http.StatusOK, resp)
}

func SetVPNTunnelHandler(c *gin.Context) {
	user := RequestGetUserInfo(c)
	var resp proto.GenerateResp
	requestID, _ := c.Get("request_id")
	resp.RequestID = requestID.(string)
	var req proto.TunnelRequestAndResponse
	if err := c.ShouldBind(&req); err != nil {
		resp.Code = proto.ParameterError
		resp.Message = "invalid parameter: " + err.Error()
	} else {
		err = service.SetMyVPNTunnelService(&user, &req, &resp)
		if err != nil {
			log.Println("[ERROR] SetVPNTunnelHandler:", err)
			resp.Message = "设置操作失败"
			resp.Code = proto.OperationFailed
		}
	}

	c.JSON(http.StatusOK, resp)
}

func GetVPNTunnelConfigHandler(c *gin.Context) {
	user := RequestGetUserInfo(c)
	var resp proto.GenerateResp
	requestID, _ := c.Get("request_id")
	resp.RequestID = requestID.(string)
	err := service.GetMyVPNTunnelService(&user, &resp)
	if err != nil {
		log.Println("[ERROR] GetVPNTunnelHandler:", err)
		resp.Message = "获取失败"
		resp.Code = proto.OperationFailed
	}

	c.JSON(http.StatusOK, resp)
}

func DeleteVPNTunnelHandler(c *gin.Context) {
	user := RequestGetUserInfo(c)
	var resp proto.GenerateResp
	requestID, _ := c.Get("request_id")
	resp.RequestID = requestID.(string)
	var req proto.TunnelRequestAndResponse
	if err := c.ShouldBind(&req); err != nil {
		resp.Code = proto.ParameterError
		resp.Message = "invalid parameter: " + err.Error()
	} else {
		err = service.DeleteMyVPNTunnelService(&user, &req, &resp)
		if err != nil {
			log.Println("[ERROR] SetVPNTunnelHandler:", err)
			resp.Message = "删除操作失败"
			resp.Code = proto.OperationFailed
		}
	}

	c.JSON(http.StatusOK, resp)
}

func GetClientConfigHandler(c *gin.Context) {
	var resp proto.GenerateResp
	user := RequestGetUserInfo(c)
	requestID, _ := c.Get("request_id")
	resp.RequestID = requestID.(string)
	serverID := c.Query("server_id")
	uuidStr := c.Query("uuid")
	if serverID == "" {
		resp.Code = proto.ParameterError
		resp.Message = "invalid parameter: server_id is required"
	} else {
		if uuidStr == "" {
			err := service.GetClientConfigService(&user, &resp, serverID)
			if err != nil {
				log.Println("[ERROR] GetClientConfigHandler:", err)
				resp.Message = "获取失败"
				resp.Code = proto.OperationFailed
			}
		} else {
			service.GetClientConfigExistService(&user, &resp, serverID, uuidStr)
		}
	}

	c.JSON(http.StatusOK, resp)
}

func GetSupportVPNServerHandler(c *gin.Context) {
	user := RequestGetUserInfo(c)
	var resp proto.GenerateResp
	requestID, _ := c.Get("request_id")
	resp.RequestID = requestID.(string)

	err := service.GetSupportVPNServerList(&user, &resp)
	if err != nil {
		log.Println("[ERROR] GetSupportVPNServerHandler:", err)
		resp.Message = "获取失败"
		resp.Code = proto.OperationFailed
	}
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
		if err != nil {
			resp.Message = err.Error()
		}
	}

	c.JSON(http.StatusOK, resp)
}

func GetServerConfigHandler(c *gin.Context) {
	user := RequestGetUserInfo(c)
	var resp proto.GenerateResp
	requestID, _ := c.Get("request_id")
	resp.RequestID = requestID.(string)
	serverID := c.Query("server_id")
	if serverID == "" {
		resp.Code = proto.ParameterError
		resp.Message = "server id is null"
	} else {
		service.GetVPNOnlineServerConfigWithAuthUser(&user, &resp, serverID)
	}
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
	user := RequestGetUserInfo(c)
	var resp proto.GenerateResp
	requestID, _ := c.Get("request_id")
	resp.RequestID = requestID.(string)
	var req proto.AddressPoolRequest
	if err := c.ShouldBind(&req); err != nil {
		resp.Code = proto.ParameterError
		resp.Message = "invalid parameter: " + err.Error()
	} else {
		err = service.SetMyVPNAddressPoolService(&user, &req, &resp)
		if err != nil {
			log.Println("[ERROR] SetVPNPoolHandler:", err)
			resp.Message = "设置操作失败"
			resp.Code = proto.OperationFailed
		}
	}

	c.JSON(http.StatusOK, resp)
}

func DeleteVPNPoolHandler(c *gin.Context) {
	user := RequestGetUserInfo(c)
	var resp proto.GenerateResp
	requestID, _ := c.Get("request_id")
	resp.RequestID = requestID.(string)
	var req proto.AddressPoolRequest
	if err := c.ShouldBind(&req); err != nil {
		resp.Code = proto.ParameterError
		resp.Message = "invalid parameter: " + err.Error()
	} else {
		err = service.DeleteMyVPNAddressPoolService(&user, &req, &resp)
		if err != nil {
			log.Println("[ERROR] SetVPNPoolHandler:", err)
			resp.Message = "删除操作失败"
			resp.Code = proto.OperationFailed
		}
	}

	c.JSON(http.StatusOK, resp)
}

func GetVPNAddressPoolHandler(c *gin.Context) {
	user := RequestGetUserInfo(c)
	var resp proto.GenerateResp
	requestID, _ := c.Get("request_id")
	resp.RequestID = requestID.(string)
	err := service.GetMyVPNAddressPoolService(&user, &resp)
	if err != nil {
		log.Println("[ERROR] SetVPNPoolHandler:", err)
		resp.Message = "获取失败"
		resp.Code = proto.OperationFailed
	}

	c.JSON(http.StatusOK, resp)
}
