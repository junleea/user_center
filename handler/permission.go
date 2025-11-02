package handler

import (
	"github.com/gin-gonic/gin"
	"log"
	"net/http"
	"user_center/proto"
	"user_center/service"
)

func SetUpPermissionGroup(router *gin.Engine) {
	permissionGroup := router.Group("/permission")

	permissionGroup.GET("/get_policy", GetPermissionPolicy)
	permissionGroup.POST("/add_policy", AddPermissionPolicy)
	permissionGroup.POST("/update_policy", UpdatePermissionPolicy)
	permissionGroup.POST("/del_policy", DelPermissionPolicy)
}

func DelPermissionPolicy(c *gin.Context) {
	user := RequestGetUserInfo(c)
	var resp proto.GenerateResp
	var req proto.PermissionPolicyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		resp.Code = proto.ParameterError
		resp.Message = "服务器解析参数错误"
	} else {
		resp.Code, err = service.DeletePermissionPolicy(&user, &req)
		if err != nil {
			resp.Message = err.Error()
		} else {
			resp.Message = "success"
		}
	}
	c.JSON(http.StatusOK, resp)
}

func UpdatePermissionPolicy(c *gin.Context) {
	user := RequestGetUserInfo(c)
	var resp proto.GenerateResp
	var req proto.PermissionPolicyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		resp.Code = proto.ParameterError
		resp.Message = "服务器解析参数错误"
	} else {
		resp.Code, err = service.UpdatePermissionPolicy(&user, &req)
		if err != nil {
			resp.Message = err.Error()
		} else {
			resp.Message = "success"
		}
	}
	c.JSON(http.StatusOK, resp)
}

func AddPermissionPolicy(c *gin.Context) {
	user := RequestGetUserInfo(c)
	var resp proto.GenerateResp
	var req proto.PermissionPolicyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		resp.Code = proto.ParameterError
		resp.Message = "服务器解析参数错误"
	} else {
		resp.Code, err = service.AddPermissionPolicy(&user, &req)
		if err != nil {
			resp.Message = err.Error()
		} else {
			resp.Message = "success"
		}
	}
	c.JSON(http.StatusOK, resp)
}

func GetPermissionPolicy(c *gin.Context) {
	user := RequestGetUserInfo(c)
	var resp proto.GenerateResp
	if user.Role == proto.USER_IS_ADMIN {
		data, err := service.GetAllPermissionInfo()
		if err != nil {
			log.Println("GetAllPermissionPolicy err:", err)
			resp.Code = proto.OperationFailed
			resp.Message = "服务器获取数据错误"
		} else {
			resp.Code = proto.SuccessCode
			resp.Data = data
		}
	} else {
		resp.Code = proto.PermissionDenied
		resp.Message = "no permission"
	}
	c.JSON(http.StatusOK, resp)
}
