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
	"github.com/go-resty/resty/v2"
	"github.com/urchinfs/hengqin-sdk/types"
	"io"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type Client interface {
	StorageVolExists(ctx context.Context, storageVolName string) (bool, error)

	MakeStorageVol(ctx context.Context, storageVolName string) (err error)

	RemoveStorageVol(ctx context.Context, storageVolName string) (err error)

	ListStorageVols(ctx context.Context) ([]StorageVolInfo, error)

	StatFile(ctx context.Context, storageVolName, fileName string) (FileInfo, error)

	GetFile(ctx context.Context, storageVolName, fileName string) (io.ReadCloser, error)

	UploadFile(ctx context.Context, storageVolName, fileName, digest string, reader io.Reader) error

	RemoveFile(ctx context.Context, storageVolName, fileName string) error

	RemoveFiles(ctx context.Context, storageVolName string, files []*FileInfo) error

	ListFiles(ctx context.Context, storageVolName, prefix, marker string, limit int64) ([]*FileInfo, error)

	ListDirFiles(ctx context.Context, storageVolName, prefix string) ([]*FileInfo, error)

	IsFileExist(ctx context.Context, storageVolName, fileName string) (bool, error)

	IsStorageVolExist(ctx context.Context, storageVolName string) (bool, error)

	GetDownloadLink(ctx context.Context, storageVolName, fileName string, expire time.Duration) (string, error)

	CreateDir(ctx context.Context, storageVolName, folderName string) error

	GetDirMetadata(ctx context.Context, storageVolName, folderKey string) (*FileInfo, bool, error)
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

type StorageVolListReply struct {
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

type StorageVolRequest struct {
	Storage string `json:"storage"`
}

type StorageVolSpec struct {
	StorageClassName string `json:"storageClassName"`
	Acl              struct {
		Project string `json:"project"`
	} `json:"acl"`
	Resources struct {
		Requests StorageVolRequest `json:"requests"`
	} `json:"resources"`
}

type StorageVolMetadata struct {
	Name   string   `json:"name"`
	Labels []string `json:"labels"`
}

type MakeStorageVolRequest struct {
	Metadata StorageVolMetadata `json:"metadata"`
	Spec     StorageVolSpec     `json:"spec"`
}

type StorageVolInfo struct {
	// The name of the storageVol.
	Name string `json:"name"`
	// Date the storageVol was created.
	CreationDate time.Time `json:"creationDate"`
}

type CreateDirReq struct {
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

		//reqToken := GetTokenRequest{
		//	Auth: struct {
		//		Identity TokenIdentity `json:"identity"`
		//		Scope    TokenScope    `json:"scope"`
		//	}{
		//		Identity: TokenIdentity{
		//			Methods: []string{"token"},
		//			Token: TokenId{
		//				Id: token,
		//			},
		//		},
		//		Scope: TokenScope{
		//			Project: AuthProject{Id: h.namespaceId},
		//		},
		//	},
		//}
		//
		//jsonBody, err = json.Marshal(reqToken)
		//if err != nil {
		//	return err
		//}
		//token, err = h.getToken(h.hqUrl+"/api/auth/v3/auth/tokens", jsonBody)
		//if err != nil {
		//	return err
		//}

		h.token = token
		h.tokenExpireTimestamp = nowTime + types.TokenExpireTime
	}

	return nil
}

type FileListReply struct {
	Items []struct {
		IsDir bool   `json:"isDir"`
		Mtime string `json:"mtime"`
		Name  string `json:"name"`
		Size  int64  `json:"size"`
	}
}

type FileInfo struct {
	Key          string
	Size         int64
	ETag         string
	ContentType  string
	LastModified time.Time
	Expires      time.Time
	Metadata     http.Header
}

func (h *client) findStorageVolByName(storageVolName string) (string, error) {
	pageIndex := 0
	const (
		pageSize = 100
	)

	for {
		hqPath := fmt.Sprintf("/api/compute/v2/namespace/%s/volume/?offset=%d&limit=%d&sort=-created_at", h.namespaceId, pageIndex, pageSize)
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

		resp := &StorageVolListReply{}
		err = json.Unmarshal(response.Body(), resp)
		if err != nil {
			return "", err
		}

		for _, storageVol := range resp.Items {
			if storageVolName == storageVol.Metadata.Name {
				return storageVol.Metadata.Uid, nil
			}
		}

		if len(resp.Items) < pageSize {
			break
		}

		pageIndex += pageSize
	}

	return "", nil
}

func (h *client) findFileByName(storageVolName, fileKey string, idDir bool) (FileInfo, error) {
	fileName := filepath.Base(fileKey)
	filePath := filepath.Dir(fileKey)
	if idDir && strings.HasSuffix(fileKey, "/") {
		filePath = filepath.Dir(filePath)
	}
	if filePath == "." || filePath == ".." {
		filePath = "/"
	}

	volumeId, err := h.findStorageVolByName(storageVolName)
	if err != nil {
		return FileInfo{}, err
	}

	hqPath := fmt.Sprintf("/api/storage/v2/namespace/%s/volume/%s/folder?path=%s", h.namespaceId, volumeId, filePath)
	response, err := h.httpClient.R().
		SetHeader(types.AuthHeader, h.token).
		Get(h.hqUrl + hqPath)
	if err != nil {
		return FileInfo{}, err
	}

	if !response.IsSuccess() {
		r := &Reply{}
		err = json.Unmarshal(response.Body(), r)
		if err != nil {
			return FileInfo{}, errors.New("internal error")
		}

		return FileInfo{}, errors.New("Code:" + strconv.FormatInt(r.Code, 10) + ", Msg:" + r.Message)
	}

	resp := &FileListReply{}
	err = json.Unmarshal(response.Body(), &resp.Items)
	if err != nil {
		return FileInfo{}, err
	}

	for _, file := range resp.Items {
		if fileName == file.Name && idDir == file.IsDir {
			timeObj, err := time.ParseInLocation(time.RFC3339Nano, file.Mtime, time.Local)
			if err != nil {
				timeObj = time.Time{}
			}

			return FileInfo{
				Key:          file.Name,
				Size:         file.Size,
				LastModified: timeObj,
			}, nil
		}
	}

	return FileInfo{}, errors.New("NoSuchKey")
}

func (h *client) StorageVolExists(ctx context.Context, storageVolName string) (bool, error) {
	if err := h.refreshToken(); err != nil {
		return false, err
	}

	volumeId, err := h.findStorageVolByName(storageVolName)
	if err != nil || volumeId == "" {
		return false, err
	}

	return true, nil
}

func (h *client) MakeStorageVol(ctx context.Context, storageVolName string) (err error) {
	if err := h.refreshToken(); err != nil {
		return err
	}

	const (
		defaultStorageVolSize = 1024 * 5
	)

	req := MakeStorageVolRequest{
		Metadata: StorageVolMetadata{
			Name:   storageVolName,
			Labels: []string{},
		},
		Spec: StorageVolSpec{
			StorageClassName: "managed-nfs-storage",
			Acl: struct {
				Project string `json:"project"`
			}{
				Project: "ReadWrite",
			},
			Resources: struct {
				Requests StorageVolRequest `json:"requests"`
			}{
				Requests: StorageVolRequest{
					Storage: strconv.FormatInt(defaultStorageVolSize, 10) + "Gi",
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

func (h *client) RemoveStorageVol(ctx context.Context, storageVolName string) (err error) {
	if err := h.refreshToken(); err != nil {
		return err
	}

	storageVolId, err := h.findStorageVolByName(storageVolName)
	if err != nil {
		return err
	}

	if storageVolId == "" {
		return errors.New("NoSuchStorageVol")
	}

	hqPath := fmt.Sprintf("/api/compute/v2/namespace/%s/volume/%s", h.namespaceId, storageVolId)
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

func (h *client) ListStorageVols(ctx context.Context) ([]StorageVolInfo, error) {
	if err := h.refreshToken(); err != nil {
		return []StorageVolInfo{}, err
	}

	pageIndex := 0
	const (
		pageSize = 100
	)

	var storageVolsInfo []StorageVolInfo
	for {
		hqPath := fmt.Sprintf("/api/compute/v2/namespace/%s/volume/?offset=%d&limit=%d&sort=-created_at", h.namespaceId, pageIndex, pageSize)
		r := &Reply{}
		response, err := h.httpClient.R().
			SetHeader(types.AuthHeader, h.token).
			SetResult(r).
			Get(h.hqUrl + hqPath)
		if err != nil {
			return storageVolsInfo, err
		}

		if !response.IsSuccess() {
			return storageVolsInfo, errors.New("NoSuchStorageVol")
		}

		resp := &StorageVolListReply{}
		err = json.Unmarshal(response.Body(), resp)
		if err != nil {
			return storageVolsInfo, err
		}

		for _, storageVol := range resp.Items {
			timeObj, err := time.ParseInLocation(time.RFC3339Nano, storageVol.Metadata.CreationTimestamp, time.Local)
			if err != nil {
				timeObj = time.Time{}
			}

			storageVolsInfo = append(storageVolsInfo, StorageVolInfo{
				Name:         storageVol.Metadata.Name,
				CreationDate: timeObj,
			})
		}

		if len(resp.Items) < pageSize {
			break
		}

		pageIndex += pageSize
	}

	return storageVolsInfo, nil
}

func (h *client) StatFile(ctx context.Context, storageVolName, fileName string) (FileInfo, error) {
	if err := h.refreshToken(); err != nil {
		return FileInfo{}, err
	}

	fileInfo, err := h.findFileByName(storageVolName, fileName, false)
	if err != nil {
		if strings.Contains(err.Error(), "doesn't exist") {
			return FileInfo{}, errors.New("NoSuchKey")
		} else {
			return FileInfo{}, err
		}
	}

	return fileInfo, nil
}

func (h *client) GetFile(ctx context.Context, storageVolName, fileName string) (io.ReadCloser, error) {
	if err := h.refreshToken(); err != nil {
		return nil, err
	}

	volumeId, err := h.findStorageVolByName(storageVolName)
	if err != nil {
		return nil, err
	}

	hqPath := fmt.Sprintf("/api/storage/v2/namespace/%s/volume/%s/file?path=%s", h.namespaceId, volumeId, fileName)
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

func (h *client) UploadFile(ctx context.Context, storageVolName, filePath, digest string, reader io.Reader) error {
	if err := h.refreshToken(); err != nil {
		return err
	}

	volumeId, err := h.findStorageVolByName(storageVolName)
	if err != nil {
		return err
	}

	fileName := filepath.Base(filePath)
	hqPath := fmt.Sprintf("/api/storage/v2/namespace/%s/volume/%s/file", h.namespaceId, volumeId)
	r := &Reply{}
	response, err := h.httpClient.R().
		SetHeader(types.AuthHeader, h.token).
		SetHeader("Content-Type", "multipart/form-data").
		SetQueryParam("path", filePath).
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

func (h *client) RemoveFile(ctx context.Context, storageVolName, fileName string) error {
	if err := h.refreshToken(); err != nil {
		return err
	}

	volumeId, err := h.findStorageVolByName(storageVolName)
	if err != nil {
		return err
	}

	hqPath := fmt.Sprintf("/api/storage/v2/namespace/%s/volume/%s/file?path=%s", h.namespaceId, volumeId, fileName)
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

func (h *client) RemoveFiles(ctx context.Context, storageVolName string, files []*FileInfo) error {
	for _, obj := range files {
		err := h.RemoveFile(ctx, storageVolName, obj.Key)
		if err != nil {
			return err
		}
	}

	return nil
}

func (h *client) ListFiles(ctx context.Context, storageVolName, prefix, marker string, limit int64) ([]*FileInfo, error) {
	if err := h.refreshToken(); err != nil {
		return nil, err
	}

	volumeId, err := h.findStorageVolByName(storageVolName)
	if err != nil {
		return nil, err
	}

	hqPath := fmt.Sprintf("/api/storage/v2/namespace/%s/volume/%s/folder?path=%s", h.namespaceId, volumeId, prefix)
	response, err := h.httpClient.R().
		SetHeader(types.AuthHeader, h.token).
		Get(h.hqUrl + hqPath)
	if err != nil {
		return []*FileInfo{}, err
	}

	if !response.IsSuccess() {
		r := &Reply{}
		err = json.Unmarshal(response.Body(), r)
		if err != nil {
			return []*FileInfo{}, errors.New("internal error")
		}

		return []*FileInfo{}, errors.New("Code:" + strconv.FormatInt(r.Code, 10) + ", Msg:" + r.Message)
	}

	resp := &FileListReply{}
	err = json.Unmarshal(response.Body(), &resp.Items)
	if err != nil {
		return []*FileInfo{}, err
	}

	var files []*FileInfo
	for _, file := range resp.Items {
		files = append(files, &FileInfo{
			Key:  file.Name,
			Size: file.Size,
		})
	}

	return files, nil
}

func (h *client) listDirObjs(volumeId, path string) ([]*FileInfo, error) {
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

	resp := &FileListReply{}
	err = json.Unmarshal(response.Body(), &resp.Items)
	if err != nil {
		return nil, err
	}

	var files []*FileInfo
	for _, file := range resp.Items {
		if !file.IsDir {
			files = append(files, &FileInfo{
				Key:  filepath.Join(path, file.Name),
				Size: file.Size,
			})
		} else {
			tmpObjs, err := h.listDirObjs(volumeId, filepath.Join(path, file.Name))
			if err != nil {
				return nil, err
			}

			files = append(files, tmpObjs...)
		}
	}

	return files, nil
}

func (h *client) ListDirFiles(ctx context.Context, storageVolName, prefix string) ([]*FileInfo, error) {
	if err := h.refreshToken(); err != nil {
		return nil, err
	}

	volumeId, err := h.findStorageVolByName(storageVolName)
	if err != nil {
		return nil, err
	}

	resp, err := h.listDirObjs(volumeId, prefix)
	if err != nil {
		return nil, err
	}

	if !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}
	resp = append(resp, &FileInfo{
		Key: prefix,
	})

	return resp, nil
}

func (h *client) IsFileExist(ctx context.Context, storageVolName, fileName string) (bool, error) {
	if err := h.refreshToken(); err != nil {
		return false, err
	}

	fileInfo, err := h.findFileByName(storageVolName, fileName, false)
	if err != nil || fileInfo.Key == "" {
		return false, err
	}

	return true, nil
}

func (h *client) IsStorageVolExist(ctx context.Context, storageVolName string) (bool, error) {
	if err := h.refreshToken(); err != nil {
		return false, err
	}

	storageVolId, err := h.findStorageVolByName(storageVolName)
	if err != nil || storageVolId == "" {
		return false, err
	}

	return true, nil
}

func (h *client) GetDownloadLink(ctx context.Context, storageVolName, fileName string, expire time.Duration) (string, error) {
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

	volumeId, err := h.findStorageVolByName(storageVolName)
	if err != nil {
		return "", err
	}

	hqPath := fmt.Sprintf("/api/storage/v2/namespace/%s/volume/%s/file?path=/%s&%s=%s",
		h.namespaceId, volumeId, fileName, strings.ToLower(types.AuthHeader), h.token)
	signedUrl := h.hqUrl + hqPath

	return signedUrl, nil
}

func (h *client) CreateDir(ctx context.Context, storageVolName, folderName string) error {
	if err := h.refreshToken(); err != nil {
		return err
	}

	req := CreateDirReq{
		Path: folderName,
	}

	jsonBody, err := json.Marshal(req)
	if err != nil {
		return err
	}

	volumeId, err := h.findStorageVolByName(storageVolName)
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

func (h *client) GetDirMetadata(ctx context.Context, storageVolName, folderKey string) (*FileInfo, bool, error) {
	if err := h.refreshToken(); err != nil {
		return nil, false, nil
	}

	folderInfo, err := h.findFileByName(storageVolName, folderKey, true)
	if err != nil {
		if strings.Contains(err.Error(), "doesn't exist") {
			return nil, false, errors.New("NoSuchKey")
		} else {
			return nil, false, err
		}
	}

	if folderInfo.Key == "" {
		return nil, false, nil
	}

	return &folderInfo, true, nil
}
