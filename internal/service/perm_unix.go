//go:build unix

package service

import (
	"os"
	"syscall"
)

// readableBy отвечает, сможет ли процесс с этим uid/gid открыть файл на чтение.
// Дополнительных групп не учитывает — для сервисного пользователя их нет.
func readableBy(path string, uid, gid int) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	if uid == 0 {
		return true // root читает всё
	}

	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	mode := info.Mode().Perm()

	switch {
	case int(stat.Uid) == uid:
		return mode&0o400 != 0
	case int(stat.Gid) == gid:
		return mode&0o040 != 0
	default:
		return mode&0o004 != 0
	}
}
