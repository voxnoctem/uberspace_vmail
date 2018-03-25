package vptable

import (
	"bytes"
	"math"
	"math/rand"
	"strconv"
	"strings"
	"time"

	crypt "github.com/amoghe/go-crypt"
)

const saltLength = 8

// VPEntry represents an entry in the VMailMgr password database
type VPEntry struct {
	Password  string
	Directory string
	Forwards  string
	Personal  string
	HardQuota uint
	SoftQuota uint
	MsgSize   uint
	MsgCount  uint
	ChangedAt time.Time
}

// UpdatePassword checks for password equality and updates the password
// when required. If the password is updated the change timestamp is
// also set to current date
func (v *VPEntry) UpdatePassword(newPass string) (bool, error) {
	oldPwdParts := strings.Split(v.Password, "$")
	salt := oldPwdParts[2]

	newPwdOldSalt, err := crypt.Crypt(newPass, "$1$"+salt+"$")
	if err != nil {
		return false, err
	}

	if newPwdOldSalt == v.Password {
		return false, nil
	}

	salt = getSalt()
	newPwd, err := crypt.Crypt(newPass, "$1$"+salt+"$")
	if err != nil {
		return false, err
	}

	v.Password = newPwd
	v.ChangedAt = time.Now()

	return true, nil
}

func (v VPEntry) encode() []byte {
	return bytes.Join([][]byte{
		[]byte("\x02\x0a\x01\x08\x01"), // 02 = prefix, 10 = attrHasMailbox, 01 = hasMailbox, 08 = attrMailboxEnabled, 01 = mailboxEnabled
		[]byte(v.Password),
		[]byte(v.Directory),
		[]byte(v.Forwards),
		[]byte(v.Personal),
		utoa(v.HardQuota),
		utoa(v.SoftQuota),
		utoa(v.MsgSize),
		utoa(v.MsgCount),
		utoa(uint(v.ChangedAt.Unix())),
		utoa(uint(math.MaxUint64)),
		{},
	}, []byte{'\x00'})
}

func parseVpentry(i []byte) *VPEntry {
	parts := bytes.Split(i, []byte{'\x00'})
	v := VPEntry{}

	v.Password = string(parts[1])
	v.Directory = string(parts[2])
	v.Forwards = string(parts[3])
	v.Personal = string(parts[4])
	v.HardQuota = atou(parts[5])
	v.SoftQuota = atou(parts[6])
	v.MsgSize = atou(parts[7])
	v.MsgCount = atou(parts[8])
	v.ChangedAt = time.Unix(int64(atou(parts[9])), 0)

	return &v
}

func utoa(u uint) []byte {
	if u == math.MaxUint64 {
		return []byte("-")
	}

	return []byte(strconv.FormatUint(uint64(u), 10))
}

func atou(i []byte) uint {
	if len(i) == 1 && i[0] == '-' {
		return uint(math.MaxUint64)
	}

	u64, err := strconv.ParseUint(string(i), 10, 64)
	if err != nil {
		panic(err)
	}

	return uint(u64)
}

func getSalt() string {
	saltSrc := "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	salt := []byte{}

	for len(salt) < saltLength {
		char := saltSrc[rand.Intn(len(saltSrc))]
		salt = append(salt, char)
	}

	return string(salt)
}
