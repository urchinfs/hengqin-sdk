/*
 *     Copyright 2022 The Urchin Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/studio-b12/gowebdav"
	"gopkg.in/resty.v1"
	"hengqin-sdk/types"
	"io"
	"log"
	"net/http"
	"net/url"
	"path/filepath"
	"strconv"
	"time"
)

type HqClient interface {
	BucketExists(ctx context.Context, bucketName string) (bool, error)

	MakeBucket(ctx context.Context, bucketName string) (err error)

	RemoveBucket(ctx context.Context, bucketName string) (err error)

	ListBuckets(ctx context.Context) ([]BucketInfo, error)

	StatObject(ctx context.Context, bucketName, objectName string) (ObjectInfo, error)

	GetObject(ctx context.Context, bucketName, objectName string) (io.ReadCloser, error)

	PutObject(ctx context.Context, bucketName, objectKey, digest string, reader io.Reader) error

	DeleteObject(ctx context.Context, bucketName, objectKey string) error

	DeleteObjects(ctx context.Context, bucketName string, objects []*ObjectInfo) error

	ListObjects(ctx context.Context, bucketName, prefix, marker string, limit int64) ([]*ObjectInfo, error)

	ListFolderObjects(ctx context.Context, bucketName, prefix string) ([]*ObjectInfo, error)

	IsObjectExist(ctx context.Context, bucketName, objectKey string) (bool, error)

	IsBucketExist(ctx context.Context, bucketName string) (bool, error)

	GetSignURL(ctx context.Context, bucketName, objectKey string, expire time.Duration) (string, error)

	CreateFolder(ctx context.Context, bucketName, folderName string) error

	GetFolderMetadata(ctx context.Context, bucketName, folderKey string) (*ObjectInfo, bool, error)
}

type hqClient struct {
	httpClient           *resty.Client
	token                string
	tokenExpireTimestamp int64
	username             string
	password             string
	namespaceId          string
	hqUrl                string
}

func NewHqClient(username, password, namespaceId, hqUrl string) (HqClient, error) {
	h := &hqClient{
		username:    username,
		password:    password,
		namespaceId: namespaceId,
		hqUrl:       hqUrl,
		httpClient:  resty.New(),
	}

	if h.username == "" || h.password == "" || h.hqUrl == "" || h.namespaceId == "" {
		return nil, errors.New("parameter error")
	}

	return h, nil
}

type AuthDomain struct {
	Id string `json:"id"`
}

type AuthUser struct {
	Name     string     `json:"name"`
	Password string     `json:"password"`
	Domain   AuthDomain `json:"domain"`
}

type AuthPassword struct {
	User AuthUser `json:"user"`
}

type AuthIdentity struct {
	Methods  []string     `json:"methods"`
	Password AuthPassword `json:"password"`
}

type AuthScope struct {
	Domain AuthDomain `json:"domain"`
}

type AuthCaptcha struct {
	Id    string      `json:"id"`
	Value interface{} `json:"value"`
}

type GetAuthRequest struct {
	Auth struct {
		Identity AuthIdentity `json:"identity"`
		Scope    AuthScope    `json:"scope"`
		Captcha  AuthCaptcha  `json:"captcha"`
	} `json:"auth"`
}

type Reply struct {
	Code    int64  `json:"code"`
	Message string `json:"message"`
}

type BucketListReply struct {
	Metadata struct {
		Total int64 `json:"total"`
	} `json:"metadata"`

	Items []struct {
		Metadata struct {
			CreationTimestamp string `json:"creationTimestamp"`
			Name              string `json:"name"`
			Namespace         string `json:"namespace"`
			Uid               string `json:"uid"`
		} `json:"metadata"`
	} `json:"items"`
}

type BucketRequest struct {
	Storage string `json:"storage"`
}

type BucketSpec struct {
	StorageClassName string   `json:"storageClassName"`
	AccessModes      []string `json:"accessModes"`
	Resources        struct {
		Requests BucketRequest `json:"requests"`
	} `json:"resources"`
}

type BucketMetadata struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
}

type MakeBucketRequest struct {
	Metadata      BucketMetadata `json:"metadata"`
	Spec          BucketSpec     `json:"spec"`
	SizeGigaBytes int64          `json:"sizeGigaBytes"`
}

type BucketInfo struct {
	// The name of the bucket.
	Name string `json:"name"`
	// Date the bucket was created.
	CreationDate time.Time `json:"creationDate"`
}

type CreateFolderReq struct {
	Path string `json:"path"`
}

type CreateFolderRePly struct {
	Code int32 `json:"code"`
}

func (h *hqClient) getToken(username, password, hqUrl string) (string, error) {
	authToken := ""
	req := GetAuthRequest{
		Auth: struct {
			Identity AuthIdentity `json:"identity"`
			Scope    AuthScope    `json:"scope"`
			Captcha  AuthCaptcha  `json:"captcha"`
		}{
			Identity: AuthIdentity{
				Methods: []string{"password"},
				Password: AuthPassword{
					User: AuthUser{
						Name:     username,
						Password: password,
						Domain:   AuthDomain{Id: "default"},
					},
				},
			},
			Scope: AuthScope{
				Domain: AuthDomain{Id: "default"},
			},
			Captcha: AuthCaptcha{},
		},
	}

	jsonBody, err := json.Marshal(req)
	if err != nil {
		return authToken, err
	}

	r := &Reply{}
	response, err := h.httpClient.R().
		SetHeader("Content-Type", "application/json").
		SetBody(jsonBody).SetResult(r).Post(hqUrl)
	if err != nil {
		return authToken, err
	}

	if !response.IsSuccess() {
		return authToken, err
	}

	if response.Header().Get(types.AuthRespHeader) == "" {
		return authToken, errors.New("authentication Failed")
	}
	authToken = response.Header().Get(types.AuthRespHeader)

	return authToken, nil
}

func (h *hqClient) refreshToken() error {
	nowTime := time.Now().Unix()
	if h.token == "" || h.tokenExpireTimestamp < nowTime {
		token, err := h.getToken(h.username, h.password, h.hqUrl+"/api/auth/v3/auth/tokens")
		if err != nil {
			return err
		}

		h.token = token
		h.tokenExpireTimestamp = nowTime + types.TokenExpireTime
	}

	return nil
}

type ObjectListReply struct {
	Items []struct {
		IsDir bool   `json:"isDir"`
		Mtime string `json:"mtime"`
		Name  string `json:"name"`
		Size  int64  `json:"size"`
	}
}

type ObjectInfo struct {
	Key          string
	Size         int64
	ETag         string
	ContentType  string
	LastModified time.Time
	Expires      time.Time
	Metadata     http.Header
}

func (h *hqClient) findBucketByName(bucketName string) (string, error) {
	hqPath := fmt.Sprintf("/api/compute/v2/namespace/%s/volume/", h.namespaceId)
	r := &Reply{}
	response, err := h.httpClient.R().
		SetHeader(types.AuthHeader, h.token).
		SetResult(r).
		Get(h.hqUrl + hqPath)
	if err != nil {
		log.Printf("findBucketByName http request failed, error:%v, inner:[%s]", err, r)
		return "", err
	}

	if !response.IsSuccess() {
		log.Printf("findBucketByName http header failed, http code:%d, inner:%s", response.StatusCode(), response.Body())
		return "", errors.New("NoSuchBucket")
	}

	resp := &BucketListReply{}
	err = json.Unmarshal(response.Body(), resp)
	if err != nil {
		log.Printf("findBucketByName json Unmarshal failed, error:%v", err)
		return "", err
	}

	for _, bucket := range resp.Items {
		if bucketName == bucket.Metadata.Name {
			return bucket.Metadata.Uid, nil
		}
	}

	return "", nil
}

func (h *hqClient) findObjectByName(bucketName, objectName string, idDir bool) (ObjectInfo, error) {
	fileName := filepath.Base(objectName)
	filePath := filepath.Dir(objectName)
	if filePath == "." || filePath == ".." {
		filePath = "/"
	}

	volumeId, err := h.findBucketByName(bucketName)
	if err != nil {
		log.Printf("can not find bucket by name[%s], err:%v", bucketName, err)
		return ObjectInfo{}, err
	}

	hqPath := fmt.Sprintf("/api/compute/v2/namespace/%s/volume/%s/folder?path=%s", h.namespaceId, volumeId, filePath)
	response, err := h.httpClient.R().
		SetHeader(types.AuthHeader, h.token).
		Get(h.hqUrl + hqPath)
	if err != nil {
		log.Printf("findObjectByName http request failed, error:%v", err)
		return ObjectInfo{}, err
	}

	if !response.IsSuccess() {
		log.Printf("findObjectByName http header failed, http code:%d, inner:%s", response.StatusCode(), response.Body())
		return ObjectInfo{}, errors.New("NoSuchBucket")
	}

	resp := &ObjectListReply{}
	err = json.Unmarshal(response.Body(), &resp.Items)
	if err != nil {
		log.Printf("findObjectByName json Unmarshal failed, error:%v", err)
		return ObjectInfo{}, err
	}

	for _, object := range resp.Items {
		if fileName == object.Name && idDir == object.IsDir {
			return ObjectInfo{
				Key:  object.Name,
				Size: object.Size,
			}, nil
		}
	}

	return ObjectInfo{}, errors.New("NoSuchObject")
}

//func PutObject_other(filePath string) {
//	bodyBuf := &bytes.Buffer{}
//	bodyWriter := multipart.NewWriter(bodyBuf)
//	fileName := filepath.Base(filePath)
//	//fileDir := filepath.Dir(filePath)
//	fileWriter, err := bodyWriter.CreateFormFile("file", fileName)
//	if err != nil {
//		log.Printf("CreateFormFile err:%v", err)
//	}
//
//	fd, _ := os.Open("E:\\Exchange_dir\\tmp\\objec_detection\\object-detection-image.zip")
//	var readCloser io.ReadCloser = fd
//	_, err = io.Copy(fileWriter, readCloser)
//
//	contentType := bodyWriter.FormDataContentType()
//	bodyWriter.Close()
//	//生成要访问的url
//	requestUrl := "https://inference.hengqinai.com:30443/api/compute/v2/"
//	requestUrl += "/namespace/f1a8a60e5878450c9c40fa57161466aa/volume/5424b620-c3e8-452b-9d56-9986043029b4/file"
//
//	data := make(url.Values)
//	data["path"] = []string{filePath}
//	uri, _ := url.Parse(requestUrl)
//	values := uri.Query()
//	if values != nil {
//		for k, v := range values {
//			data[k] = v
//		}
//	}
//	uri.RawQuery = data.Encode()
//
//	request, err := http.NewRequest(http.MethodPost, uri.String(), bodyBuf)
//	if err != nil {
//		log.Printf("NewRequest err:%v", err)
//	}
//	request.Header.Add("x-auth-token", Token)
//	request.Header.Add("Content-Type", contentType)
//	request.Header.Add("Content-Type", "multipart/form-data")
//	client := &http.Client{}
//	//处理返回结果
//	response, _ := client.Do(request)
//	if response.StatusCode/100 != 2 {
//		log.Printf("Upload bad resp status %v", response.StatusCode)
//	}
//	defer response.Body.Close()
//
//	body, err := io.ReadAll(response.Body)
//
//	log.Printf("'resp;%s", body)
//
//}

func (h *hqClient) BucketExists(ctx context.Context, bucketName string) (bool, error) {
	if err := h.refreshToken(); err != nil {
		return false, err
	}

	volumeId, err := h.findBucketByName(bucketName)
	if err != nil || volumeId == "" {
		return false, err
	}

	return true, nil
}

func (h *hqClient) MakeBucket(ctx context.Context, bucketName string) (err error) {
	if err := h.refreshToken(); err != nil {
		return err
	}

	const (
		defaultBucketSize = 1024 * 5
	)

	req := MakeBucketRequest{
		Metadata: BucketMetadata{
			Name:      bucketName,
			Namespace: h.namespaceId,
		},
		Spec: BucketSpec{
			StorageClassName: "parastor",
			AccessModes:      []string{"ReadWriteMany"},
			Resources: struct {
				Requests BucketRequest `json:"requests"`
			}{
				Requests: BucketRequest{
					Storage: strconv.FormatInt(defaultBucketSize, 10) + "Gi",
				},
			},
		},
		SizeGigaBytes: defaultBucketSize,
	}

	jsonBody, err := json.Marshal(req)
	if err != nil {
		log.Printf("getHengQinToken json Marshal failed, error:%v", err)
		return err
	}

	hqPath := fmt.Sprintf("/api/compute/v2/namespace/%s/volume", h.namespaceId)
	r := &Reply{}
	response, err := h.httpClient.R().
		SetHeader("Content-Type", "application/json").
		SetHeader(types.AuthHeader, h.token).
		SetBody(jsonBody).
		SetResult(r).
		Post(h.hqUrl + hqPath)
	if err != nil {
		log.Printf("h.httpClient http request failed, error:%v, inner:[%v]", err, r)
		return err
	}
	if !response.IsSuccess() {
		log.Printf("h.httpClient http header failed, http code:%d, inner:%s", response.StatusCode(), response.Body())
		return fmt.Errorf("http status code:%d", response.StatusCode())
	}

	log.Printf("'resp code:%v", response.StatusCode())
	return nil
}

func (h *hqClient) RemoveBucket(ctx context.Context, bucketName string) (err error) {
	if err := h.refreshToken(); err != nil {
		return err
	}

	bucketId, err := h.findBucketByName(bucketName)
	if err != nil {
		return err
	}

	if bucketId == "" {
		return errors.New("NoSuchBucket")
	}

	hqPath := fmt.Sprintf("/api/compute/v2/namespace/%s/volume/%s", h.namespaceId, bucketId)
	r := &Reply{}
	response, err := h.httpClient.R().
		SetHeader(types.AuthHeader, h.token).
		SetResult(r).
		Delete(h.hqUrl + hqPath)
	if err != nil {
		log.Printf("h.httpClient http request failed, error:%v, inner:[%v]", err, r)
		return err
	}
	if !response.IsSuccess() {
		log.Printf("h.httpClient http header failed, http code:%d, inner:%s", response.StatusCode(), response.Body())
		return fmt.Errorf("http status code:%d", response.StatusCode())
	}

	log.Printf("'resp code:%v", response.StatusCode())
	return nil
}

func (h *hqClient) ListBuckets(ctx context.Context) ([]BucketInfo, error) {
	if err := h.refreshToken(); err != nil {
		return []BucketInfo{}, err
	}

	var bucketsInfo []BucketInfo
	hqPath := fmt.Sprintf("/api/compute/v2/namespace/%s/volume/", h.namespaceId)
	r := &Reply{}
	response, err := h.httpClient.R().
		SetHeader(types.AuthHeader, h.token).
		SetResult(r).
		Get(h.hqUrl + hqPath)
	if err != nil {
		log.Printf("getCreatedTaskId http request failed, error:%v, inner:[%s]", err, r)
		return bucketsInfo, err
	}

	if !response.IsSuccess() {
		log.Printf("getCreatedTaskId http header failed, http code:%d, inner:%s", response.StatusCode(), response.Body())
		return bucketsInfo, errors.New("NoSuchBucket")
	}

	resp := &BucketListReply{}
	err = json.Unmarshal(response.Body(), resp)
	if err != nil {
		log.Printf("getCreatedTaskId json Unmarshal failed, error:%v", err)
		return bucketsInfo, err
	}

	for _, bucket := range resp.Items {
		timeObj, err := time.ParseInLocation(time.RFC3339Nano, bucket.Metadata.CreationTimestamp, time.Local)
		if err != nil {
			timeObj = time.Time{}
		}

		bucketsInfo = append(bucketsInfo, BucketInfo{
			Name:         bucket.Metadata.Name,
			CreationDate: timeObj,
		})
	}

	return bucketsInfo, nil
}

func (h *hqClient) StatObject(ctx context.Context, bucketName, objectName string) (ObjectInfo, error) {
	if err := h.refreshToken(); err != nil {
		return ObjectInfo{}, err
	}

	objectInfo, err := h.findObjectByName(bucketName, objectName, false)
	if err != nil {
		log.Printf("findObjectByName failed, error:%v", err)
		return ObjectInfo{}, err
	}

	return objectInfo, nil
}

func (h *hqClient) GetObject(ctx context.Context, bucketName, objectName string) (io.ReadCloser, error) {
	if err := h.refreshToken(); err != nil {
		return nil, err
	}

	volumeId, err := h.findBucketByName(bucketName)
	if err != nil {
		log.Printf("can not find bucket by name[%s], err:%v", bucketName, err)
		return nil, err
	}

	hqPath := fmt.Sprintf("/api/compute/v2/namespace/%s/volume/%s/file?path=%s", h.namespaceId, volumeId, objectName)
	response, err := h.httpClient.R().
		SetHeader(types.AuthHeader, h.token).
		SetDoNotParseResponse(true).
		Get(h.hqUrl + hqPath)
	if err != nil {
		log.Printf("findObjectByName http request failed, error:%v", err)
		return nil, err
	}

	if !response.IsSuccess() {
		log.Printf("findObjectByName http header failed, http code:%d, inner:%s", response.StatusCode(), response.Body())
		return nil, errors.New("NoSuchBucket")
	}

	return response.RawBody(), nil
}

//func getObjectToFile(hqClient HqClient, bucketName, objectName string) error {
//	reader, err := hqClient.GetObject(context.TODO(), bucketName, objectName)
//	if err == nil {
//		//file, err := os.Create("D:\\Work_dir\\Tmp\\example.txt")
//		file, err := os.Create("D:\\Work_dir\\Tmp\\example_202302016_002.dat")
//		if err != nil {
//			log.Printf("os.Create err:%v", err)
//		}
//		_, err = io.Copy(file, reader)
//		if err != nil {
//			log.Printf("io.Copy err:%v", err)
//		}
//	} else {
//		return err
//	}
//
//	return nil
//}

//func (h *hqClient) PutObject222(filePath string) {
//	fileName := filepath.Base(filePath)
//	//fd, _ := os.Open("../data/nydus-static-v2.1.0-alpha.4-linux-amd64.tgz")
//	fd, _ := os.Open("E:\\Exchange_dir\\tmp\\objec_detection\\object-detection-image.zip")
//	var readCloser io.ReadCloser = fd
//
//	hqPath := fmt.Sprintf("/api/compute/v2/namespace/%s/volume/%s/file", NamespaceId, MyVolumeId)
//	r := &Reply{}
//	response, err := h.httpClient.R().
//		SetHeader(authHeader, Token).
//		SetHeader("Content-Type", "multipart/form-data").
//		SetQueryParam("path", filePath).
//		SetFileReader("file", fileName, readCloser).
//		SetResult(r).
//		Post(HengQinUrl + hqPath)
//	if err != nil {
//		log.Printf("h.httpClient http request failed, error:%v, inner:[%v]", err, r)
//		return
//	}
//	if !response.IsSuccess() {
//		log.Printf("getCreatedTaskId http header failed, http code:%d, inner:%s", response.StatusCode(), response.Body())
//		return
//	}
//
//	log.Printf("'resp code:%v", response.StatusCode())
//
//}

func (h *hqClient) PutObject(ctx context.Context, bucketName, objectKey, digest string, reader io.Reader) error {
	if err := h.refreshToken(); err != nil {
		return err
	}

	volumeId, err := h.findBucketByName(bucketName)
	if err != nil {
		log.Printf("can not find bucket by name[%s], err:%v", bucketName, err)
		return err
	}

	fileName := filepath.Base(objectKey)
	hqPath := fmt.Sprintf("/api/compute/v2/namespace/%s/volume/%s/file", h.namespaceId, volumeId)
	r := &Reply{}
	response, err := h.httpClient.R().
		SetHeader(types.AuthHeader, h.token).
		SetHeader("Content-Type", "multipart/form-data").
		SetQueryParam("path", objectKey).
		SetFileReader("file", fileName, reader).
		SetResult(r).
		Post(h.hqUrl + hqPath)
	if err != nil {
		log.Printf("h.httpClient http request failed, error:%v, inner:[%v]", err, r)
		return err
	}
	if !response.IsSuccess() {
		log.Printf("PutObject http header failed, http code:%d, inner:%s", response.StatusCode(), response.Body())
		return err
	}

	return nil
}

func (h *hqClient) DeleteObject(ctx context.Context, bucketName, objectKey string) error {
	if err := h.refreshToken(); err != nil {
		return err
	}

	volumeId, err := h.findBucketByName(bucketName)
	if err != nil {
		log.Printf("can not find bucket by name[%s], err:%v", bucketName, err)
		return err
	}

	hqPath := fmt.Sprintf("/api/compute/v2/namespace/%s/volume/%s/file?path=%s", h.namespaceId, volumeId, objectKey)
	response, err := h.httpClient.R().
		SetHeader(types.AuthHeader, h.token).
		Delete(h.hqUrl + hqPath)
	if err != nil {
		log.Printf("findObjectByName http request failed, error:%v", err)
		return err
	}

	if !response.IsSuccess() {
		return errors.New("NoSuchObject")
	}

	return nil
}

func (h *hqClient) DeleteObjects(ctx context.Context, bucketName string, objects []*ObjectInfo) error {
	for _, obj := range objects {
		err := h.DeleteObject(ctx, bucketName, obj.Key)
		if err != nil {
			return err
		}
	}

	return nil
}

func (h *hqClient) ListObjects(ctx context.Context, bucketName, prefix, marker string, limit int64) ([]*ObjectInfo, error) {
	if err := h.refreshToken(); err != nil {
		return nil, err
	}

	volumeId, err := h.findBucketByName(bucketName)
	if err != nil {
		log.Printf("can not find bucket by name[%s], err:%v", bucketName, err)
		return nil, err
	}

	hqPath := fmt.Sprintf("/api/compute/v2/namespace/%s/volume/%s/folder?path=%s", h.namespaceId, volumeId, prefix)
	response, err := h.httpClient.R().
		SetHeader(types.AuthHeader, h.token).
		Get(h.hqUrl + hqPath)
	if err != nil {
		log.Printf("findObjectByName http request failed, error:%v", err)
		return []*ObjectInfo{}, err
	}

	if !response.IsSuccess() {
		log.Printf("findObjectByName http header failed, http code:%d, inner:%s", response.StatusCode(), response.Body())
		return []*ObjectInfo{}, errors.New("NoSuchBucket")
	}

	resp := &ObjectListReply{}
	err = json.Unmarshal(response.Body(), &resp.Items)
	if err != nil {
		log.Printf("findObjectByName json Unmarshal failed, error:%v", err)
		return []*ObjectInfo{}, err
	}

	var obejcts []*ObjectInfo
	for _, object := range resp.Items {
		obejcts = append(obejcts, &ObjectInfo{
			Key:  object.Name,
			Size: object.Size,
		})
	}

	return obejcts, nil
}

func (h *hqClient) listFolderObjs(volumeId, path string) ([]*ObjectInfo, error) {
	if path == "." || path == ".." {
		return nil, nil
	}

	hqPath := fmt.Sprintf("/api/compute/v2/namespace/%s/volume/%s/folder?path=%s", h.namespaceId, volumeId, path)
	response, err := h.httpClient.R().
		SetHeader(types.AuthHeader, h.token).
		Get(h.hqUrl + hqPath)
	if err != nil {
		log.Printf("findObjectByName http request failed, error:%v", err)
		return nil, err
	}

	if !response.IsSuccess() {
		log.Printf("findObjectByName http header failed, http code:%d, inner:%s", response.StatusCode(), response.Body())
		return nil, errors.New("NoSuchBucket")
	}

	resp := &ObjectListReply{}
	err = json.Unmarshal(response.Body(), &resp.Items)
	if err != nil {
		log.Printf("findObjectByName json Unmarshal failed, error:%v", err)
		return nil, err
	}

	var objects []*ObjectInfo
	for _, object := range resp.Items {
		if !object.IsDir {
			objects = append(objects, &ObjectInfo{
				Key:  object.Name,
				Size: object.Size,
			})
		} else {
			tmpObjs, err := h.listFolderObjs(volumeId, filepath.Join(path+object.Name))
			if err != nil {
				return nil, err
			}

			objects = append(objects, tmpObjs...)
		}
	}

	return objects, nil
}

func (h *hqClient) ListFolderObjects(ctx context.Context, bucketName, prefix string) ([]*ObjectInfo, error) {
	if err := h.refreshToken(); err != nil {
		return nil, err
	}

	volumeId, err := h.findBucketByName(bucketName)
	if err != nil {
		log.Printf("can not find bucket by name[%s], err:%v", bucketName, err)
		return nil, err
	}

	return h.listFolderObjs(volumeId, prefix)
}

func (h *hqClient) IsObjectExist(ctx context.Context, bucketName, objectKey string) (bool, error) {
	if err := h.refreshToken(); err != nil {
		return false, err
	}

	objectInfo, err := h.findObjectByName(bucketName, objectKey, false)
	if err != nil || objectInfo.Key == "" {
		return false, err
	}

	return true, nil
}

func (h *hqClient) IsBucketExist(ctx context.Context, bucketName string) (bool, error) {
	if err := h.refreshToken(); err != nil {
		return false, err
	}

	bucketId, err := h.findBucketByName(bucketName)
	if err != nil || bucketId == "" {
		return false, err
	}

	log.Printf("bucketName:%v, bucketId:%v", bucketName, bucketId)
	return true, nil
}

func (h *hqClient) GetSignURL(ctx context.Context, bucketName, objectKey string, expire time.Duration) (string, error) {
	const (
		DefaultSignedUrlTime = 60 * 60 * 6
	)
	nowTime := time.Now().Unix()
	if h.tokenExpireTimestamp-nowTime < DefaultSignedUrlTime {
		h.token = ""
	}

	if err := h.refreshToken(); err != nil {
		return "", err
	}

	volumeId, err := h.findBucketByName(bucketName)
	if err != nil {
		log.Printf("can not find bucket by name[%s], err:%v", bucketName, err)
		return "", err
	}

	hqPath := fmt.Sprintf("/api/compute/v2/namespace/%s/volume/%s/file", h.namespaceId, volumeId)
	reqUrl := h.hqUrl + hqPath

	data := make(url.Values)
	data["path"] = []string{objectKey}
	data["token"] = []string{h.token}
	uri, _ := url.Parse(reqUrl)
	uri.RawQuery = data.Encode()

	return uri.String(), nil
}

func (h *hqClient) CreateFolder(ctx context.Context, bucketName, folderName string) error {
	if err := h.refreshToken(); err != nil {
		return err
	}

	req := CreateFolderReq{
		Path: folderName,
	}

	jsonBody, err := json.Marshal(req)
	if err != nil {
		return err
	}

	volumeId, err := h.findBucketByName(bucketName)
	if err != nil {
		log.Printf("can not find bucket by name[%s], err:%v", bucketName, err)
		return err
	}

	hqPath := fmt.Sprintf("/api/compute/v2/namespace/%s/volume/%s/folder", h.namespaceId, volumeId)
	r := &Reply{}
	response, err := h.httpClient.R().
		SetHeader("Content-Type", "application/json").
		SetBody(jsonBody).
		SetResult(r).
		Post(h.hqUrl + hqPath)
	if err != nil {
		return err
	}

	if !response.IsSuccess() {
		return err
	}

	//---
	resp := &CreateFolderRePly{}
	err = json.Unmarshal(response.Body(), &resp)
	if err != nil {
		log.Printf("CreateFolder json Unmarshal failed, error:%v", err)
		return err
	}

	if resp.Code != 0 {
		return errors.New("xxxxxxxxx")
	}

	return nil
}

func (h *hqClient) GetFolderMetadata(ctx context.Context, bucketName, folderKey string) (*ObjectInfo, bool, error) {
	if err := h.refreshToken(); err != nil {
		return nil, false, nil
	}

	folderInfo, err := h.findObjectByName(bucketName, folderKey, true)
	if err != nil || folderInfo.Key == "" {
		return nil, false, err
	}

	return &folderInfo, false, nil
}

// - init client
func initHqClient() (HqClient, error) {
	hqClient, err := NewHqClient("111", "222", types.NamespaceId, types.HengQinUrl)
	if err != nil {
		return nil, err
	}

	return hqClient, nil
}

func goTest() {
	root := "https://inference.hengqinai.com:30443"
	user := "cloudbrain_register@pcl.ac.cn"
	password := "XZzgwzpcHtj0nG0F5qT0"

	log.Printf("new gowebdav")
	c := gowebdav.NewClient(root, user, password)

	log.Printf("gowebdav read dir")
	files, _ := c.ReadDir(":webdav:/api/compute/namespace/f1a8a60e5878450c9c40fa57161466aa/volume/5424b620-c3e8-452b-9d56-9986043029b4/dir1")
	for _, file := range files {
		//notice that [file] has os.FileInfo type
		log.Printf(file.Name())
	}

}

func main() {
	log.Printf("start.......")

	hqClient, err := initHqClient()
	if err != nil {
		log.Printf("init HqClient failed, err:%v", err)
	}

	//put_object2("dir1/test/code.rar")
	//PutObject_other("dir1/test/object-detection-image222.zip")
	//PutObject("dir1/test/object-detection-image.zip")
	//PutObject("nydus-static-v2.1.0-alpha.4-linux-amd64.tgz")

	//isExist, _ := hqClient.BucketExists(context.TODO(), "my-vol-test")
	//log.Printf("BucketExists:%v", isExist)

	//_ = hqClient.MakeBucket(context.TODO(), "glin-vol-001")
	//_ = hqClient.RemoveBucket(context.TODO(), "glin-vol-001")
	//buckets, _ := hqClient.ListBuckets(context.TODO())
	//log.Printf("buckets:%v", buckets)

	//- test api
	objectInfo, _ := hqClient.StatObject(context.TODO(), "my-vol-test", "dir1/test/bootstramp")
	log.Printf("objectInfo:%v", objectInfo)

	//-next...
	//objectInfo, _ := StatObject(context.TODO(), "my-vol-test", "dir1/test/code.rar")
	//log.Printf("objectInfo:%v", objectInfo)

	//_ = getObjectToFile(hqClient, "my-vol-test", "dir1/test/jupyter-object-detection-notebook.zip")

	//_ = hqClient.DeleteObject(context.TODO(), "my-vol-test", "dir1/test/bootstrap")

	//objects := []*ObjectInfo{
	//	{Key: "dir1/vision.cpp"},
	//	{Key: "dir1/box_encode.h"},
	//	{Key: "dir1/bootstrap"},
	//	{Key: "dir1/anchor_generator.h"},
	//	{Key: "dir1/Xshell-7.0.0111.exe"},
	//}
	//_ = hqClient.DeleteObjects(context.TODO(), "my-vol-test", objects)

	//metadatas, _ := hqClient.ListObjectMetadatas(context.TODO(), "my-vol-test", "dir1/hub/core", "1", 10)
	//for _, object := range metadatas {
	//	log.Printf("metadatas:%v:%v", object.Key, object.Size)
	//}

	//exist, err := hqClient.IsObjectExist(context.TODO(), "my-vol-test", "dir1/test/bootstrap")
	//log.Printf("IsObjectExist exist:%v", exist)

	//exist, err := hqClient.IsBucketExist(context.TODO(), "my-vol-test")
	//log.Printf("IsBucketExist exist:%v", exist)

	//signURL, _ := hqClient.GetSignURL(context.TODO(), "my-vol-test", "/dir1/test/bootstrap", 1*60*time.Minute)
	//log.Printf("signURL:%s", signURL)

	//goTest()

	log.Printf("end.......")
}
