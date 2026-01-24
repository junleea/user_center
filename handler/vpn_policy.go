package handler

import (
	"context"
	"encoding/json"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"log"
	"net/http"
	"strconv"
	"user_center/dao"
	"user_center/proto"
	"user_center/service"
	"user_center/worker"
)

var upgrader = websocket.Upgrader{
	// 允许跨域（开发环境下，生产环境需根据实际配置）
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
}

func SetUpMyVPNPolicyGroup(router *gin.Engine) {
	myVPNPolicyGroup := router.Group("/vpn_policy")
	myVPNPolicyGroup.GET("/get", GetMyVPNPolicyHandler)
	myVPNPolicyGroup.POST("/create", CreateMyVPNPolicyHandler)
	myVPNPolicyGroup.POST("/update", UpdateMyVPNPolicyHandler)
	myVPNPolicyGroup.DELETE("/delete", DeleteMyVPNPolicyHandler)
	myVPNPolicyGroup.POST("/match", MatchMyVPNPolicyHandler)
}
func MatchMyVPNPolicyHandler(c *gin.Context) {
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
	} else {
		service.MatchMyVPNPolicy(&user, &req, &resp)
	}
	c.JSON(http.StatusOK, resp)
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

func DPServerConnectWSHandler(c *gin.Context) {
	user := RequestGetUserInfo(c)
	var resp proto.GenerateResp
	if user.Role != proto.USER_IS_ADMIN && user.Role != proto.ROLE_VPN_SERVER {
		resp.Code = proto.PermissionDenied
		resp.Message = "no permission"
		c.JSON(http.StatusOK, resp)
		return
	}
	serverID := c.Query("server_id")
	if serverID == "" {
		resp.Code = proto.ParameterError
		resp.Message = "server id is null"
		c.JSON(http.StatusOK, resp)
		return
	}
	// 升级HTTP连接为WebSocket连接
	ws, err1 := upgrader.Upgrade(c.Writer, c.Request, nil)
	if err1 != nil {
		log.Println("升级为WebSocket时发生错误:", err1)
		resp.Code = proto.InternalServerError
		resp.Message = err1.Error()
		c.JSON(http.StatusOK, resp)
		return
	}
	handleDPServerMessage(ws, &user, serverID)
}

func handleDPServerMessage(ws *websocket.Conn, user *dao.User, serverID string) {
	ctx := context.Background()
	channel := "vpn_dp_event_" + serverID
	pubSub := worker.RedisClient.Subscribe(ctx, channel)

	defer func() {
		err := pubSub.Close()
		if err != nil {
			log.Println("server id:", serverID, " close sub err:", err)
		}
		err = ws.Close()
		if err != nil {
			log.Println("server id:", serverID, " close ws err:", err)
		}
	}()

	// 从 pubSub 获取消息并发送到客户端
	go func() {
		for {
			msg, err := pubSub.ReceiveMessage(ctx)
			if err != nil {
				log.Println("server id:", serverID, " receive pubSub message err:", err)
				break
			}
			err = ws.WriteMessage(websocket.TextMessage, []byte(msg.Payload))
			if err != nil {
				log.Println("server id:", serverID, " write to ws err:", err)
				break
			}
		}
	}()

	// 接收客户端消息并处理
	for {
		_, message, err := ws.ReadMessage()
		if err != nil {
			log.Println("server id:", serverID, " read from ws err:", err)
			break
		}
		// 根据需要处理客户端消息
		go handleReceiveDPServerMessage(message, user)
	}
}

func handleReceiveDPServerMessage(msg []byte, user *dao.User) {
	var req proto.VPNDPServerEvent
	err := json.Unmarshal(msg, &req)
	if err != nil {
		log.Println("receive dp server msg decode err:", err)
		return
	}
}
