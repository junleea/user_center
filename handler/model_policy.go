package handler

import (
	"github.com/gin-gonic/gin"
	"log"
	"net/http"
	"user_center/proto"
	"user_center/service"
)

func SetUpModelPolicyGroup(router *gin.Engine) {
	modelPolicyGroup := router.Group("/model_policy")

	modelPolicyGroup.GET("/get_policy", GetModelPolicy)
	modelPolicyGroup.POST("/add_policy", AddModelPolicy)
	modelPolicyGroup.POST("/update_policy", UpdateModelPolicy)
	modelPolicyGroup.POST("/del_policy", DelModelPolicy)
}

func DelModelPolicy(c *gin.Context) {
	user := RequestGetUserInfo(c)
	var resp proto.GenerateResp
	var req proto.ModelPolicyRequest
	requestID, _ := c.Get("request_id")
	resp.RequestID = requestID.(string)
	if err := c.ShouldBind(&req); err != nil {
		resp.Code = proto.ParameterError
		resp.Message = "服务器解析参数错误"
		log.Println("[ERROR] request_id: ", resp.RequestID, ", decode request fail:", err.Error())
	} else {
		resp.Code, err = service.DeleteModelPolicy(resp.RequestID, &user, &req)
		if err != nil {
			resp.Message = err.Error()
		} else {
			resp.Message = "success"
		}
	}
	c.JSON(http.StatusOK, resp)
}

func UpdateModelPolicy(c *gin.Context) {
	user := RequestGetUserInfo(c)
	var resp proto.GenerateResp
	var req proto.ModelPolicyRequest
	requestID, _ := c.Get("request_id")
	resp.RequestID = requestID.(string)
	if err := c.ShouldBind(&req); err != nil {
		resp.Code = proto.ParameterError
		resp.Message = "服务器解析参数错误"
		log.Println("[ERROR] request_id: ", resp.RequestID, ", decode request fail:", err.Error())
	} else {
		resp.Code, err = service.UpdateUserModelPolicy(&user, &req, resp.RequestID)
		if err != nil {
			resp.Message = err.Error()
		} else {
			resp.Message = "success"
		}
	}
	c.JSON(http.StatusOK, resp)
}

func AddModelPolicy(c *gin.Context) {
	user := RequestGetUserInfo(c)
	var resp proto.GenerateResp
	var req proto.ModelPolicyRequest
	requestID, _ := c.Get("request_id")
	resp.RequestID = requestID.(string)
	if err := c.ShouldBind(&req); err != nil {
		resp.Code = proto.ParameterError
		resp.Message = "服务器解析参数错误"
		log.Println("[ERROR] request_id: ", resp.RequestID, ", decode request fail:", err.Error())
	} else {
		resp.Code, err = service.AddUserModelPolicy(resp.RequestID, &user, &req)
		if err != nil {
			resp.Message = err.Error()
		} else {
			resp.Message = "success"
		}
	}
	c.JSON(http.StatusOK, resp)
}

func GetModelPolicy(c *gin.Context) {
	user := RequestGetUserInfo(c)
	var resp proto.GenerateResp
	if user.Role == proto.USER_IS_ADMIN {
		var req proto.GetUserModelPolicyRequest
		if err := c.ShouldBindQuery(&req); err != nil {
			resp.Code = proto.OperationFailed
			resp.Message = "服务器获取数据错误"
			log.Println("[ERROR] request id:", resp.RequestID, " decode GetModelPolicy request fail:", err.Error())
		} else {
			if req.Type == 0 {
				data, err2 := service.GetAllModelPolicyInfo()
				if err2 != nil {
					log.Println("GetAllPermissionPolicy err:", err)
					resp.Code = proto.OperationFailed
					resp.Message = "服务器获取数据错误"
				} else {
					resp.Code = proto.SuccessCode
					resp.Data = data
				}
			} else if req.Type == 1 {
				data, err2 := service.GetUserModelInfo(&req)
				if err2 != nil {
					log.Println("GetUserPermissionPolicy err:", err)
					resp.Code = proto.OperationFailed
					resp.Message = "服务器获取数据错误"
				} else {
					resp.Code = proto.SuccessCode
					resp.Data = data
				}
			} else {
				if req.ModelPolicyID <= 0 {
					resp.Code = proto.ParameterError
					resp.Message = "policy id is  invalid"

				} else {
					data, err2 := service.GetOneModelPolicyInfo(req.ModelPolicyID)
					if err2 != nil {
						log.Println("GetUserPermissionPolicy err:", err)
						resp.Code = proto.OperationFailed
						resp.Message = "服务器获取数据错误"
					} else {
						resp.Code = proto.SuccessCode
						resp.Data = data
					}
				}
			}
		}
	} else {
		resp.Code = proto.PermissionDenied
		resp.Message = "no permission"
	}
	c.JSON(http.StatusOK, resp)
}
