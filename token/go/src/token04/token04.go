package token04

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/rand"
	"time"

	"github.com/zegoim/zego_server_assistant/token/go/src/errors"
	"github.com/zegoim/zego_server_assistant/token/go/src/util"
)

// 权限位定义
const (
	PrivilegeKeyLogin   = 1 // 是否启用登录鉴权
	PrivilegeKeyPublish = 2 // 是否启用推流鉴权
)

// 权限开关定义
const (
	PrivilegeEnable  = 1 // 开启
	PrivilegeDisable = 0 // 关闭
)

// AES加密模式
const (
	AesEncryptModeCBCPKCS5Padding = 0 // AES加密模式: AES/CBC/PKCS5Padding； 废弃
	AesEncryptModeGCM             = 1 // AES加密模式: AES/GCM；推荐使用
)

type TokenInfo04 struct {
	AppId   uint32 `json:"app_id"`
	UserId  string `json:"user_id"`
	CTime   int64  `json:"ctime"`
	Expire  int64  `json:"expire"`
	Nonce   int32  `json:"nonce"`
	PayLoad string `json:"payload"`
}

// 生成04版本的token
func GenerateToken04(appId uint32, userId string, secret string, effectiveTimeInSeconds int64, payload string) (token string, err error) {
	if appId == 0 {
		return "", errors.NewZegoSDKError(errors.InvalidParamErrorCode, "appId Invalid")
	}
	if userId == "" {
		return "", errors.NewZegoSDKError(errors.InvalidParamErrorCode, "userId Invalid")
	}
	if len(secret) != 32 {
		return "", errors.NewZegoSDKError(errors.InvalidParamErrorCode, "secret Invalid")
	}
	if effectiveTimeInSeconds <= 0 {
		return "", errors.NewZegoSDKError(errors.InvalidParamErrorCode, "effectiveTimeInSeconds Invalid")
	}

	tokenInfo := TokenInfo04{
		AppId:   appId,
		UserId:  userId,
		CTime:   time.Now().Unix(),
		Expire:  0,
		Nonce:   makeNonce(),
		PayLoad: payload,
	}
	tokenInfo.Expire = tokenInfo.CTime + effectiveTimeInSeconds

	// 把token信息转成json
	plaintText, err := json.Marshal(tokenInfo)
	if err != nil {
		return "", err
	}

	// 加密
	cryptedBuf, nonce, err := util.AesGCMEncrypt(plaintText, []byte(secret))
	if err != nil {
		return "", fmt.Errorf("AesGCMEncrypt error:%v, plaintText:%s, nonce:%s", err, string(plaintText), string(nonce))
	}

	// len+data
	resultSize := len(cryptedBuf) + len(nonce) + 13
	result := bytes.NewBuffer(make([]byte, 0, resultSize))

	// 打包数据
	err = util.PackInt64(result, tokenInfo.Expire)
	if err != nil {
		return "", fmt.Errorf("PackData1 error:%v, timeout:%d, result:%v", err, tokenInfo.Expire, result)
	}
	err = util.PackString(result, string(nonce))
	if err != nil {
		return "", fmt.Errorf("PackData2 error:%v, nonce:%s, result:%v", err, string(nonce), result)
	}
	err = util.PackString(result, string(cryptedBuf))
	if err != nil {
		return "", fmt.Errorf("PackData3 error:%v, cryptedData:%s, result:%v", err, string(cryptedBuf), result)
	}
	err = util.PackUint8(result, AesEncryptModeGCM)
	if err != nil {
		return "", fmt.Errorf("PackData4 error:%v, AesEncryptMode:%d, result:%v", err, AesEncryptModeGCM, result)
	}

	token = "04" + base64.StdEncoding.EncodeToString(result.Bytes())
	return token, nil
}

func makeNonce() int32 {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	return r.Int31()
}
