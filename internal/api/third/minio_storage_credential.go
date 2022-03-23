package apiThird

import (
	apiStruct "Open_IM/pkg/base_info"
	"Open_IM/pkg/common/config"
	"Open_IM/pkg/common/constant"
	"Open_IM/pkg/common/log"
	"Open_IM/pkg/common/token_verify"
	_ "Open_IM/pkg/common/token_verify"
	"Open_IM/pkg/utils"
	"context"
	"github.com/gin-gonic/gin"
	"github.com/minio/minio-go/v7"
	_ "github.com/minio/minio-go/v7"
	cr "github.com/minio/minio-go/v7/pkg/credentials"
	"net/http"
)

func MinioUploadFile(c *gin.Context) {
	var (
		req  apiStruct.MinioUploadFileReq
		resp apiStruct.MinioUploadFileResp
	)
	defer func() {
		if r := recover(); r != nil {
			log.NewError(req.OperationID, recover())
			log.NewError(req.OperationID, utils.GetSelfFuncName(), r)
			c.JSON(http.StatusBadRequest, gin.H{"errCode": 400, "errMsg": r})
			return
		}
	}()
	if err := c.Bind(&req); err != nil {
		log.NewError("0", utils.GetSelfFuncName(), "BindJSON failed ", err.Error())
		c.JSON(http.StatusBadRequest, gin.H{"errCode": 400, "errMsg": err.Error()})
		return
	}
	log.NewInfo(req.OperationID, utils.GetSelfFuncName(), req)
	switch req.FileType {
	case constant.VideoType:
		snapShotFile, _ := c.FormFile("snapShot")
		snapShotFileObj, err := snapShotFile.Open()
		if err != nil {
			log.NewError(req.OperationID, utils.GetSelfFuncName(), "Open file error", err.Error())
			c.JSON(http.StatusBadRequest, gin.H{"errCode": 400, "errMsg": err.Error()})
			return
		}
		snapShotNewName, snapShotNewType := utils.GetNewFileNameAndContentType(snapShotFile.Filename)
		_, err = minioClient.PutObject(context.Background(), config.Config.Credential.Minio.Bucket, snapShotNewName, snapShotFileObj, snapShotFile.Size, minio.PutObjectOptions{ContentType: snapShotNewType})
		if err != nil {
			log.NewError(req.OperationID, utils.GetSelfFuncName(), "PutObject snapShotFile error", err.Error())
			c.JSON(http.StatusBadRequest, gin.H{"errCode": 400, "errMsg": err.Error()})
			return
		}
		resp.SnapshotURL = config.Config.Credential.Minio.Endpoint + "/" + config.Config.Credential.Minio.Bucket + "/" + snapShotNewName
		resp.SnapshotNewName = snapShotNewName
	}
	file, _ := c.FormFile("file")
	fileObj, err := file.Open()
	if err != nil {
		log.NewError(req.OperationID, utils.GetSelfFuncName(), "Open file error", err.Error())
		c.JSON(http.StatusBadRequest, gin.H{"errCode": 400, "errMsg": "invalid file path" + err.Error()})
		return
	}
	newName, newType := utils.GetNewFileNameAndContentType(file.Filename)
	_, err = minioClient.PutObject(context.Background(), config.Config.Credential.Minio.Bucket, newName, fileObj, file.Size, minio.PutObjectOptions{ContentType: newType})
	if err != nil {
		log.NewError(req.OperationID, utils.GetSelfFuncName(), "open file error")
		c.JSON(http.StatusBadRequest, gin.H{"errCode": 400, "errMsg": "invalid file path" + err.Error()})
		return
	}
	resp.NewName = newName
	resp.URL = config.Config.Credential.Minio.Endpoint + "/" + config.Config.Credential.Minio.Bucket + "/" + newName
	log.NewInfo(req.OperationID, utils.GetSelfFuncName(), "resp: ", resp)
	c.JSON(http.StatusOK, gin.H{"errCode": 0, "errMsg": "", "data": resp})
	return
}

func MinioStorageCredential(c *gin.Context) {
	var (
		req  apiStruct.MinioStorageCredentialReq
		resp apiStruct.MiniostorageCredentialResp
	)
	if err := c.BindJSON(&req); err != nil {
		log.NewError("0", utils.GetSelfFuncName(), "BindJSON failed ", err.Error())
		c.JSON(http.StatusBadRequest, gin.H{"errCode": 400, "errMsg": err.Error()})
		return
	}
	ok, _ := token_verify.GetUserIDFromToken(c.Request.Header.Get("token"), req.OperationID)
	if !ok {
		log.NewError("", utils.GetSelfFuncName(), "GetUserIDFromToken false ", c.Request.Header.Get("token"))
		c.JSON(http.StatusInternalServerError, gin.H{"errCode": 500, "errMsg": "GetUserIDFromToken failed"})
		return
	}
	var stsOpts cr.STSAssumeRoleOptions
	stsOpts.AccessKey = config.Config.Credential.Minio.AccessKeyID
	stsOpts.SecretKey = config.Config.Credential.Minio.SecretAccessKey
	stsOpts.DurationSeconds = constant.MinioDurationTimes
	li, err := cr.NewSTSAssumeRole(config.Config.Credential.Minio.Endpoint, stsOpts)
	if err != nil {
		log.NewError("", utils.GetSelfFuncName(), "NewSTSAssumeRole failed", err.Error(), stsOpts, config.Config.Credential.Minio.Endpoint)
		c.JSON(http.StatusBadRequest, gin.H{"errCode": 400, "errMsg": err.Error()})
		return
	}
	v, err := li.Get()
	if err != nil {
		log.NewError("0", utils.GetSelfFuncName(), "li.Get error", err.Error())
		c.JSON(http.StatusBadRequest, gin.H{"errCode": 400, "errMsg": err.Error()})
		return
	}
	resp.SessionToken = v.SessionToken
	resp.SecretAccessKey = v.SecretAccessKey
	resp.AccessKeyID = v.AccessKeyID
	resp.BucketName = config.Config.Credential.Minio.Bucket
	resp.StsEndpointURL = config.Config.Credential.Minio.Endpoint
	c.JSON(http.StatusOK, gin.H{"errCode": 0, "errMsg": "", "data": resp})
}
