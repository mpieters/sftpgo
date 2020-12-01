package dataprovider

import (
	"github.com/drakkan/sftpgo/vfs"
)

type compatUserV2 struct {
	ID                int64    `json:"id"`
	Username          string   `json:"username"`
	Password          string   `json:"password,omitempty"`
	PublicKeys        []string `json:"public_keys,omitempty"`
	HomeDir           string   `json:"home_dir"`
	UID               int      `json:"uid"`
	GID               int      `json:"gid"`
	MaxSessions       int      `json:"max_sessions"`
	QuotaSize         int64    `json:"quota_size"`
	QuotaFiles        int      `json:"quota_files"`
	Permissions       []string `json:"permissions"`
	UsedQuotaSize     int64    `json:"used_quota_size"`
	UsedQuotaFiles    int      `json:"used_quota_files"`
	LastQuotaUpdate   int64    `json:"last_quota_update"`
	UploadBandwidth   int64    `json:"upload_bandwidth"`
	DownloadBandwidth int64    `json:"download_bandwidth"`
	ExpirationDate    int64    `json:"expiration_date"`
	LastLogin         int64    `json:"last_login"`
	Status            int      `json:"status"`
}

type compatS3FsConfigV4 struct {
	Bucket            string `json:"bucket,omitempty"`
	KeyPrefix         string `json:"key_prefix,omitempty"`
	Region            string `json:"region,omitempty"`
	AccessKey         string `json:"access_key,omitempty"`
	AccessSecret      string `json:"access_secret,omitempty"`
	Endpoint          string `json:"endpoint,omitempty"`
	StorageClass      string `json:"storage_class,omitempty"`
	UploadPartSize    int64  `json:"upload_part_size,omitempty"`
	UploadConcurrency int    `json:"upload_concurrency,omitempty"`
}

type compatGCSFsConfigV4 struct {
	Bucket               string `json:"bucket,omitempty"`
	KeyPrefix            string `json:"key_prefix,omitempty"`
	CredentialFile       string `json:"-"`
	Credentials          []byte `json:"credentials,omitempty"`
	AutomaticCredentials int    `json:"automatic_credentials,omitempty"`
	StorageClass         string `json:"storage_class,omitempty"`
}

type compatAzBlobFsConfigV4 struct {
	Container         string `json:"container,omitempty"`
	AccountName       string `json:"account_name,omitempty"`
	AccountKey        string `json:"account_key,omitempty"`
	Endpoint          string `json:"endpoint,omitempty"`
	SASURL            string `json:"sas_url,omitempty"`
	KeyPrefix         string `json:"key_prefix,omitempty"`
	UploadPartSize    int64  `json:"upload_part_size,omitempty"`
	UploadConcurrency int    `json:"upload_concurrency,omitempty"`
	UseEmulator       bool   `json:"use_emulator,omitempty"`
	AccessTier        string `json:"access_tier,omitempty"`
}

type compatFilesystemV4 struct {
	Provider     FilesystemProvider     `json:"provider"`
	S3Config     compatS3FsConfigV4     `json:"s3config,omitempty"`
	GCSConfig    compatGCSFsConfigV4    `json:"gcsconfig,omitempty"`
	AzBlobConfig compatAzBlobFsConfigV4 `json:"azblobconfig,omitempty"`
}

type compatUserV4 struct {
	ID                int64               `json:"id"`
	Status            int                 `json:"status"`
	Username          string              `json:"username"`
	ExpirationDate    int64               `json:"expiration_date"`
	Password          string              `json:"password,omitempty"`
	PublicKeys        []string            `json:"public_keys,omitempty"`
	HomeDir           string              `json:"home_dir"`
	VirtualFolders    []vfs.VirtualFolder `json:"virtual_folders,omitempty"`
	UID               int                 `json:"uid"`
	GID               int                 `json:"gid"`
	MaxSessions       int                 `json:"max_sessions"`
	QuotaSize         int64               `json:"quota_size"`
	QuotaFiles        int                 `json:"quota_files"`
	Permissions       map[string][]string `json:"permissions"`
	UsedQuotaSize     int64               `json:"used_quota_size"`
	UsedQuotaFiles    int                 `json:"used_quota_files"`
	LastQuotaUpdate   int64               `json:"last_quota_update"`
	UploadBandwidth   int64               `json:"upload_bandwidth"`
	DownloadBandwidth int64               `json:"download_bandwidth"`
	LastLogin         int64               `json:"last_login"`
	Filters           UserFilters         `json:"filters"`
	FsConfig          compatFilesystemV4  `json:"filesystem"`
}

type backupDataV4Compat struct {
	Users   []compatUserV4          `json:"users"`
	Folders []vfs.BaseVirtualFolder `json:"folders"`
}

func createUserFromV4(u compatUserV4, fsConfig Filesystem) User {
	user := User{
		ID:                u.ID,
		Status:            u.Status,
		Username:          u.Username,
		ExpirationDate:    u.ExpirationDate,
		Password:          u.Password,
		PublicKeys:        u.PublicKeys,
		HomeDir:           u.HomeDir,
		VirtualFolders:    u.VirtualFolders,
		UID:               u.UID,
		GID:               u.GID,
		MaxSessions:       u.MaxSessions,
		QuotaSize:         u.QuotaSize,
		QuotaFiles:        u.QuotaFiles,
		Permissions:       u.Permissions,
		UsedQuotaSize:     u.UsedQuotaSize,
		UsedQuotaFiles:    u.UsedQuotaFiles,
		LastQuotaUpdate:   u.LastQuotaUpdate,
		UploadBandwidth:   u.UploadBandwidth,
		DownloadBandwidth: u.DownloadBandwidth,
		LastLogin:         u.LastLogin,
		Filters:           u.Filters,
	}
	user.FsConfig = fsConfig
	return user
}

func convertUserToV4(u User, fsConfig compatFilesystemV4) compatUserV4 {
	user := compatUserV4{
		ID:                u.ID,
		Status:            u.Status,
		Username:          u.Username,
		ExpirationDate:    u.ExpirationDate,
		Password:          u.Password,
		PublicKeys:        u.PublicKeys,
		HomeDir:           u.HomeDir,
		VirtualFolders:    u.VirtualFolders,
		UID:               u.UID,
		GID:               u.GID,
		MaxSessions:       u.MaxSessions,
		QuotaSize:         u.QuotaSize,
		QuotaFiles:        u.QuotaFiles,
		Permissions:       u.Permissions,
		UsedQuotaSize:     u.UsedQuotaSize,
		UsedQuotaFiles:    u.UsedQuotaFiles,
		LastQuotaUpdate:   u.LastQuotaUpdate,
		UploadBandwidth:   u.UploadBandwidth,
		DownloadBandwidth: u.DownloadBandwidth,
		LastLogin:         u.LastLogin,
		Filters:           u.Filters,
	}
	user.FsConfig = fsConfig
	return user
}

func convertFsConfigToV4(fs Filesystem, username string) (compatFilesystemV4, error) {
	fsV4 := compatFilesystemV4{
		Provider: fs.Provider,
	}
	return fsV4, nil
}

func convertFsConfigFromV4(compatFs compatFilesystemV4, username string) (Filesystem, error) {
	fsConfig := Filesystem{
		Provider: compatFs.Provider,
	}
	return fsConfig, nil
}
