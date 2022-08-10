package im_mysql_model

import (
	"Open_IM/pkg/common/db"
	"Open_IM/pkg/utils"
	"strings"

	"github.com/google/uuid"
)

// type GroupKey struct {
// 	UserID     string    `gorm:"column:user_id;primary_key;size:64"`
// 	GroupID    string    `gorm:"column:group_id;primary_key;size:64"`
// 	Key        string    `gorm:"column:key;size:64"`
// 	CreateTime time.Time `gorm:"column:create_time"`
// 	Ex         string    `gorm:"column:ex;size:1024"`
// }

func InsertIntoGroupKey(toInsertInfo db.GroupKey) error {

	toInsertInfo.CreateTime = utils.UnixSecondToTime(0)
	// generate key
	_uuid, _ := uuid.NewUUID()
	key := strings.ReplaceAll(_uuid.String(), "-", "")
	toInsertInfo.Key = key

	err := db.DB.MysqlDB.DefaultGormDB().Table("group_keys").Create(&toInsertInfo).Error
	if err != nil {
		return err
	}
	return nil
}

func GetGroupKeyByGroupID(groupID string) ([]db.GroupKey, error) {
	var groupRequestList []db.GroupKey
	err := db.DB.MysqlDB.DefaultGormDB().Table("group_keys").Where("group_id=?", groupID).Find(&groupRequestList).Error
	if err != nil {
		return nil, err
	}
	return groupRequestList, nil
}
