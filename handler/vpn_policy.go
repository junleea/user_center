package handler

import (
	"github.com/gin-gonic/gin"
	"net/http"
	"strconv"
	"user_center/proto"
	"user_center/service"
)

func SetUpMyVPNPolicyGroup(router *gin.Engine) {
	myVPNPolicyGroup := router.Group("/vpn_policy")
	myVPNPolicyGroup.GET("/get", GetMyVPNPolicyHandler)
	myVPNPolicyGroup.POST("/create", CreateMyVPNPolicyHandler)
	myVPNPolicyGroup.POST("/update", UpdateMyVPNPolicyHandler)
	myVPNPolicyGroup.DELETE("/delete", DeleteMyVPNPolicyHandler)
}

func GetMyVPNPolicyHandler(c *gin.Context) {
	user := RequestGetUserInfo(c)
	var resp proto.GenerateResp
	requestID, _ := c.Get("request_id")
	resp.Code = proto.SuccessCode
	resp.Message = "success"
	resp.RequestID = requestID.(string)
	server_id := c.Query("server_id")
	if server_id == "" {
		resp.Code = proto.ParameterError
		resp.Message = "server id is null"
	} else {
		service.GetMyVPNPolicyByServerID(&user, &resp, server_id)
	}
	c.JSON(http.StatusOK, resp)
}

func CreateMyVPNPolicyHandler(c *gin.Context) {
	user := RequestGetUserInfo(c)
	var resp proto.GenerateResp
	requestID, _ := c.Get("request_id")
	resp.Code = proto.SuccessCode
	resp.Message = "success"
	resp.RequestID = requestID.(string)

	var req proto.VPNPolicyRequest
	if err := c.ShouldBind(&req); err != nil {
		resp.Code = proto.ParameterError
		resp.Message = "invalid request parameters"
		c.JSON(http.StatusBadRequest, resp)
		return
	}

	service.CreateMyVPNPolicy(&user, &resp, &req)
	c.JSON(http.StatusOK, resp)
}

func UpdateMyVPNPolicyHandler(c *gin.Context) {
	user := RequestGetUserInfo(c)
	var resp proto.GenerateResp
	requestID, _ := c.Get("request_id")
	resp.Code = proto.SuccessCode
	resp.Message = "success"
	resp.RequestID = requestID.(string)

	var req proto.VPNPolicyRequest
	if err := c.ShouldBind(&req); err != nil {
		resp.Code = proto.ParameterError
		resp.Message = "invalid request parameters"
		c.JSON(http.StatusBadRequest, resp)
		return
	}

	service.UpdateMyVPNPolicy(&user, &resp, &req)
	c.JSON(http.StatusOK, resp)
}

func DeleteMyVPNPolicyHandler(c *gin.Context) {
	user := RequestGetUserInfo(c)
	var resp proto.GenerateResp
	requestID, _ := c.Get("request_id")
	resp.Code = proto.SuccessCode
	resp.Message = "success"
	resp.RequestID = requestID.(string)
	serverID := c.Query("server_id")

	policyID := c.Query("id")
	if policyID == "" && serverID == "" {
		resp.Code = proto.ParameterError
		resp.Message = "policy id is null"
		c.JSON(http.StatusBadRequest, resp)
		return
	}

	id, err := strconv.ParseUint(policyID, 10, 32)
	if err != nil {
		resp.Code = proto.ParameterError
		resp.Message = "invalid policy id"
		c.JSON(http.StatusBadRequest, resp)
		return
	}

	service.DeleteMyVPNPolicy(&user, &resp, uint(id), serverID)
	c.JSON(http.StatusOK, resp)
}
