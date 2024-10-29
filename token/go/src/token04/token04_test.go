package token04

import (
	"encoding/json"
	"testing"
)

func Test_GenerateToken04(t *testing.T) {
	var appId uint32 = 1
	userId := "demo-token04"
	serverSecret := "fa94dd0f974cf2e293728a526b028271"
	var effectiveTimeInSeconds int64 = 3600
	var payload string = ""

	token, err := GenerateToken04(appId, userId, serverSecret, effectiveTimeInSeconds, payload)
	if err != nil {
		t.Error(err)
		return
	}
	t.Log(token)
}

// token业务扩展：权限认证属性
type RtcRoomPayLoad struct {
	RoomId       string      `json:"room_id"`        //房间id；用于对接口的房间id进行强验证
	Privilege    map[int]int `json:"privilege"`      //权限位开关列表；用于对接口的操作权限进行强验证
	StreamIdList []string    `json:"stream_id_list"` //流列表；用于对接口的流id进行强验证；允许为空，如果为空，则不对流id验证
}

func Test_GenerateToken04_RtcRoom(t *testing.T) {
	var appId uint32 = 1
	roomId := "demo-room"
	userId := "demo-token04"
	serverSecret := "fa94dd0f974cf2e293728a526b028271"
	var effectiveTimeInSeconds int64 = 3600

	//业务权限认证配置，可以配置多个权限位
	privilege := make(map[int]int)
	privilege[PrivilegeKeyLogin] = PrivilegeEnable    //允许房间登录
	privilege[PrivilegeKeyPublish] = PrivilegeDisable //不允许推流

	//token业务扩展配置
	payloadData := &RtcRoomPayLoad{
		RoomId:       roomId,
		Privilege:    privilege,
		StreamIdList: nil,
	}

	payload, err := json.Marshal(payloadData)
	if err != nil {
		t.Error(err)
		return
	}

	token, err := GenerateToken04(appId, userId, serverSecret, effectiveTimeInSeconds, string(payload))
	if err != nil {
		t.Error(err)
		return
	}
	t.Log(token)
}
