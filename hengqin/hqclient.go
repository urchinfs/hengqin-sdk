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

package hengqin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/urchinfs/hengqin-sdk/types"
	"gopkg.in/resty.v1"
	"io"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type Client interface {
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

type client struct {
	httpClient           *resty.Client
	token                string
	tokenExpireTimestamp int64
	username             string
	password             string
	namespaceId          string
	hqUrl                string
}

func New(username, password, namespaceId, hqUrl string) (Client, error) {
	h := &client{
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

type AuthProject struct {
	Id string `json:"id"`
}

type TokenId struct {
	Id string `json:"id"`
}

type TokenIdentity struct {
	Methods []string `json:"methods"`
	Token   TokenId  `json:"token"`
}

type TokenScope struct {
	Project AuthProject `json:"project"`
}

type GetTokenRequest struct {
	Auth struct {
		Identity TokenIdentity `json:"identity"`
		Scope    TokenScope    `json:"scope"`
	} `json:"auth"`
}

type GetAuthRequest struct {
	Identity string `json:"identity"`
	Password string `json:"password"`
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
	StorageClassName string `json:"storageClassName"`
	Acl              struct {
		Project string `json:"project"`
	} `json:"acl"`
	Resources struct {
		Requests BucketRequest `json:"requests"`
	} `json:"resources"`
}

type BucketMetadata struct {
	Name   string   `json:"name"`
	Labels []string `json:"labels"`
}

type MakeBucketRequest struct {
	Metadata BucketMetadata `json:"metadata"`
	Spec     BucketSpec     `json:"spec"`
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

func (h *client) getToken(hqUrl string, jsonBody []byte) (string, error) {
	r := &Reply{}
	response, err := h.httpClient.R().
		SetHeader("Content-Type", "application/json").
		SetBody(jsonBody).SetResult(r).Post(hqUrl)
	if err != nil {
		return "", err
	}

	if !response.IsSuccess() {
		return "", err
	}

	if response.Header().Get(types.AuthRespHeader) == "" {
		return "", errors.New("authentication Failed")
	}
	authToken := response.Header().Get(types.AuthRespHeader)

	return authToken, nil
}

func (h *client) refreshToken() error {
	nowTime := time.Now().Unix()
	if h.token == "" || h.tokenExpireTimestamp < nowTime {
		req := GetAuthRequest{
			Identity: h.username,
			Password: h.password,
		}

		jsonBody, err := json.Marshal(req)
		if err != nil {
			return err
		}

		token, err := h.getToken(h.hqUrl+"/api/auth/v3/login/internal", jsonBody)
		if err != nil {
			return err
		}

		reqToken := GetTokenRequest{
			Auth: struct {
				Identity TokenIdentity `json:"identity"`
				Scope    TokenScope    `json:"scope"`
			}{
				Identity: TokenIdentity{
					Methods: []string{"token"},
					Token: TokenId{
						Id: token,
					},
				},
				Scope: TokenScope{
					Project: AuthProject{Id: h.namespaceId},
				},
			},
		}

		jsonBody, err = json.Marshal(reqToken)
		if err != nil {
			return err
		}
		token, err = h.getToken(h.hqUrl+"/api/auth/v3/auth/tokens", jsonBody)
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

func (h *client) findBucketByName(bucketName string) (string, error) {
	hqPath := fmt.Sprintf("/api/compute/v2/namespace/%s/volume/", h.namespaceId)
	r := &Reply{}
	response, err := h.httpClient.R().
		SetHeader(types.AuthHeader, h.token).
		SetResult(r).
		Get(h.hqUrl + hqPath)
	if err != nil {
		return "", err
	}

	if !response.IsSuccess() {
		r := &Reply{}
		err = json.Unmarshal(response.Body(), r)
		if err != nil {
			return "", errors.New("NoSuchBucket")
		}

		return "", errors.New("Code:" + strconv.FormatInt(r.Code, 10) + ", Msg:" + r.Message)
	}

	resp := &BucketListReply{}
	err = json.Unmarshal(response.Body(), resp)
	if err != nil {
		return "", err
	}

	for _, bucket := range resp.Items {
		if bucketName == bucket.Metadata.Name {
			return bucket.Metadata.Uid, nil
		}
	}

	return "", nil
}

func (h *client) findObjectByName(bucketName, objectName string, idDir bool) (ObjectInfo, error) {
	fileName := filepath.Base(objectName)
	filePath := filepath.Dir(objectName)
	if filePath == "." || filePath == ".." {
		filePath = "/"
	}

	volumeId, err := h.findBucketByName(bucketName)
	if err != nil {
		return ObjectInfo{}, err
	}

	hqPath := fmt.Sprintf("/api/storage/v2/namespace/%s/volume/%s/folder?path=%s", h.namespaceId, volumeId, filePath)
	response, err := h.httpClient.R().
		SetHeader(types.AuthHeader, h.token).
		Get(h.hqUrl + hqPath)
	if err != nil {
		return ObjectInfo{}, err
	}

	if !response.IsSuccess() {
		r := &Reply{}
		err = json.Unmarshal(response.Body(), r)
		if err != nil {
			return ObjectInfo{}, errors.New("internal error")
		}

		return ObjectInfo{}, errors.New("Code:" + strconv.FormatInt(r.Code, 10) + ", Msg:" + r.Message)
	}

	resp := &ObjectListReply{}
	err = json.Unmarshal(response.Body(), &resp.Items)
	if err != nil {
		return ObjectInfo{}, err
	}

	for _, object := range resp.Items {
		if fileName == object.Name && idDir == object.IsDir {
			timeObj, err := time.ParseInLocation(time.RFC3339Nano, object.Mtime, time.Local)
			if err != nil {
				timeObj = time.Time{}
			}

			return ObjectInfo{
				Key:          object.Name,
				Size:         object.Size,
				LastModified: timeObj,
			}, nil
		}
	}

	return ObjectInfo{}, errors.New("NoSuchKey")
}

func (h *client) BucketExists(ctx context.Context, bucketName string) (bool, error) {
	if err := h.refreshToken(); err != nil {
		return false, err
	}

	volumeId, err := h.findBucketByName(bucketName)
	if err != nil || volumeId == "" {
		return false, err
	}

	return true, nil
}

func (h *client) MakeBucket(ctx context.Context, bucketName string) (err error) {
	if err := h.refreshToken(); err != nil {
		return err
	}

	const (
		defaultBucketSize = 1024 * 5
	)

	req := MakeBucketRequest{
		Metadata: BucketMetadata{
			Name:   bucketName,
			Labels: []string{},
		},
		Spec: BucketSpec{
			StorageClassName: "managed-nfs-storage",
			Acl: struct {
				Project string `json:"project"`
			}{
				Project: "ReadWrite",
			},
			Resources: struct {
				Requests BucketRequest `json:"requests"`
			}{
				Requests: BucketRequest{
					Storage: strconv.FormatInt(defaultBucketSize, 10) + "Gi",
				},
			},
		},
	}

	jsonBody, err := json.Marshal(req)
	if err != nil {
		return err
	}

	hqPath := fmt.Sprintf("/api/compute/v2/namespace/%s/volume", h.namespaceId)
	response, err := h.httpClient.R().
		SetHeader("Content-Type", "application/json").
		SetHeader(types.AuthHeader, h.token).
		SetBody(jsonBody).
		Post(h.hqUrl + hqPath)
	if err != nil {
		return err
	}
	if !response.IsSuccess() {
		r := &Reply{}
		err = json.Unmarshal(response.Body(), r)
		if err != nil {
			return errors.New("internal error")
		}

		return errors.New("Code:" + strconv.FormatInt(r.Code, 10) + ", Msg:" + r.Message)
	}

	return nil
}

func (h *client) RemoveBucket(ctx context.Context, bucketName string) (err error) {
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
		return err
	}
	if !response.IsSuccess() {
		return fmt.Errorf("http status code:%d", response.StatusCode())
	}

	return nil
}

func (h *client) ListBuckets(ctx context.Context) ([]BucketInfo, error) {
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
		return bucketsInfo, err
	}

	if !response.IsSuccess() {
		return bucketsInfo, errors.New("NoSuchBucket")
	}

	resp := &BucketListReply{}
	err = json.Unmarshal(response.Body(), resp)
	if err != nil {
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

func (h *client) StatObject(ctx context.Context, bucketName, objectName string) (ObjectInfo, error) {
	if err := h.refreshToken(); err != nil {
		return ObjectInfo{}, err
	}

	objectInfo, err := h.findObjectByName(bucketName, objectName, false)
	if err != nil {
		return ObjectInfo{}, err
	}

	return objectInfo, nil
}

func (h *client) GetObject(ctx context.Context, bucketName, objectName string) (io.ReadCloser, error) {
	if err := h.refreshToken(); err != nil {
		return nil, err
	}

	volumeId, err := h.findBucketByName(bucketName)
	if err != nil {
		return nil, err
	}

	hqPath := fmt.Sprintf("/api/storage/v2/namespace/%s/volume/%s/file?path=%s", h.namespaceId, volumeId, objectName)
	response, err := h.httpClient.R().
		SetHeader(types.AuthHeader, h.token).
		SetDoNotParseResponse(true).
		Get(h.hqUrl + hqPath)
	if err != nil {
		return nil, err
	}

	if !response.IsSuccess() {
		r := &Reply{}
		err = json.Unmarshal(response.Body(), r)
		if err != nil {
			return nil, errors.New("internal error")
		}

		return nil, errors.New("Code:" + strconv.FormatInt(r.Code, 10) + ", Msg:" + r.Message)
	}

	return response.RawBody(), nil
}

func (h *client) PutObject(ctx context.Context, bucketName, objectKey, digest string, reader io.Reader) error {
	if err := h.refreshToken(); err != nil {
		return err
	}

	volumeId, err := h.findBucketByName(bucketName)
	if err != nil {
		return err
	}

	fileName := filepath.Base(objectKey)
	hqPath := fmt.Sprintf("/api/storage/v2/namespace/%s/volume/%s/file", h.namespaceId, volumeId)
	r := &Reply{}
	response, err := h.httpClient.R().
		SetHeader(types.AuthHeader, h.token).
		SetHeader("Content-Type", "multipart/form-data").
		SetQueryParam("path", objectKey).
		SetFileReader("file", fileName, reader).
		SetResult(r).
		Post(h.hqUrl + hqPath)
	if err != nil {
		return err
	}
	if !response.IsSuccess() {
		r := &Reply{}
		err = json.Unmarshal(response.Body(), r)
		if err != nil {
			return errors.New("internal error")
		}

		return errors.New("Code:" + strconv.FormatInt(r.Code, 10) + ", Msg:" + r.Message)
	}

	return nil
}

func (h *client) DeleteObject(ctx context.Context, bucketName, objectKey string) error {
	if err := h.refreshToken(); err != nil {
		return err
	}

	volumeId, err := h.findBucketByName(bucketName)
	if err != nil {
		return err
	}

	hqPath := fmt.Sprintf("/api/storage/v2/namespace/%s/volume/%s/file?path=%s", h.namespaceId, volumeId, objectKey)
	response, err := h.httpClient.R().
		SetHeader(types.AuthHeader, h.token).
		Delete(h.hqUrl + hqPath)
	if err != nil {
		return err
	}

	if !response.IsSuccess() {
		return errors.New("NoSuchKey")
	}

	return nil
}

func (h *client) DeleteObjects(ctx context.Context, bucketName string, objects []*ObjectInfo) error {
	for _, obj := range objects {
		err := h.DeleteObject(ctx, bucketName, obj.Key)
		if err != nil {
			return err
		}
	}

	return nil
}

func (h *client) ListObjects(ctx context.Context, bucketName, prefix, marker string, limit int64) ([]*ObjectInfo, error) {
	if err := h.refreshToken(); err != nil {
		return nil, err
	}

	volumeId, err := h.findBucketByName(bucketName)
	if err != nil {
		return nil, err
	}

	hqPath := fmt.Sprintf("/api/storage/v2/namespace/%s/volume/%s/folder?path=%s", h.namespaceId, volumeId, prefix)
	response, err := h.httpClient.R().
		SetHeader(types.AuthHeader, h.token).
		Get(h.hqUrl + hqPath)
	if err != nil {
		return []*ObjectInfo{}, err
	}

	if !response.IsSuccess() {
		r := &Reply{}
		err = json.Unmarshal(response.Body(), r)
		if err != nil {
			return []*ObjectInfo{}, errors.New("internal error")
		}

		return []*ObjectInfo{}, errors.New("Code:" + strconv.FormatInt(r.Code, 10) + ", Msg:" + r.Message)
	}

	resp := &ObjectListReply{}
	err = json.Unmarshal(response.Body(), &resp.Items)
	if err != nil {
		return []*ObjectInfo{}, err
	}

	var objects []*ObjectInfo
	for _, object := range resp.Items {
		objects = append(objects, &ObjectInfo{
			Key:  object.Name,
			Size: object.Size,
		})
	}

	return objects, nil
}

func (h *client) listFolderObjs(volumeId, path string) ([]*ObjectInfo, error) {
	if path == "." || path == ".." {
		return nil, nil
	}

	hqPath := fmt.Sprintf("/api/storage/v2/namespace/%s/volume/%s/folder?path=%s", h.namespaceId, volumeId, path)
	response, err := h.httpClient.R().
		SetHeader(types.AuthHeader, h.token).
		Get(h.hqUrl + hqPath)
	if err != nil {
		return nil, err
	}

	if !response.IsSuccess() {

		r := &Reply{}
		err = json.Unmarshal(response.Body(), r)
		if err != nil {
			return nil, errors.New("internal error")
		}

		return nil, errors.New("Code:" + strconv.FormatInt(r.Code, 10) + ", Msg:" + r.Message)
	}

	resp := &ObjectListReply{}
	err = json.Unmarshal(response.Body(), &resp.Items)
	if err != nil {
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
			tmpObjs, err := h.listFolderObjs(volumeId, filepath.Join(path, object.Name))
			if err != nil {
				return nil, err
			}

			objects = append(objects, tmpObjs...)
		}
	}

	return objects, nil
}

func (h *client) ListFolderObjects(ctx context.Context, bucketName, prefix string) ([]*ObjectInfo, error) {
	if err := h.refreshToken(); err != nil {
		return nil, err
	}

	volumeId, err := h.findBucketByName(bucketName)
	if err != nil {
		return nil, err
	}

	return h.listFolderObjs(volumeId, prefix)
}

func (h *client) IsObjectExist(ctx context.Context, bucketName, objectKey string) (bool, error) {
	if err := h.refreshToken(); err != nil {
		return false, err
	}

	objectInfo, err := h.findObjectByName(bucketName, objectKey, false)
	if err != nil || objectInfo.Key == "" {
		return false, err
	}

	return true, nil
}

func (h *client) IsBucketExist(ctx context.Context, bucketName string) (bool, error) {
	if err := h.refreshToken(); err != nil {
		return false, err
	}

	bucketId, err := h.findBucketByName(bucketName)
	if err != nil || bucketId == "" {
		return false, err
	}

	return true, nil
}

func (h *client) GetSignURL(ctx context.Context, bucketName, objectKey string, expire time.Duration) (string, error) {
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
		return "", err
	}

	hqPath := fmt.Sprintf("/api/storage/v2/namespace/%s/volume/%s/file?path=/%s&%s=%s",
		h.namespaceId, volumeId, objectKey, strings.ToLower(types.AuthHeader), h.token)
	signedUrl := h.hqUrl + hqPath

	return signedUrl, nil
}

func (h *client) CreateFolder(ctx context.Context, bucketName, folderName string) error {
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
		return err
	}

	hqPath := fmt.Sprintf("/api/storage/v2/namespace/%s/volume/%s/folder", h.namespaceId, volumeId)
	response, err := h.httpClient.R().
		SetHeader("Content-Type", "application/json").
		SetHeader(types.AuthHeader, h.token).
		SetBody(jsonBody).
		Post(h.hqUrl + hqPath)
	if err != nil {
		return err
	}

	if !response.IsSuccess() {
		r := &Reply{}
		err = json.Unmarshal(response.Body(), r)
		if err != nil {
			return errors.New("internal error")
		}

		return errors.New("Code:" + strconv.FormatInt(r.Code, 10) + ", Msg:" + r.Message)
	}

	return nil
}

func (h *client) GetFolderMetadata(ctx context.Context, bucketName, folderKey string) (*ObjectInfo, bool, error) {
	if err := h.refreshToken(); err != nil {
		return nil, false, nil
	}

	folderInfo, err := h.findObjectByName(bucketName, folderKey, true)
	if err != nil || folderInfo.Key == "" {
		return nil, false, err
	}

	return &folderInfo, true, nil
}
