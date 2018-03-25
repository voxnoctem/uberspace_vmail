package main

import (
	"fmt"
	"math"
	"net/url"
	"os"
	"path"
	"strings"
	"time"

	"github.com/Luzifer/go_helpers/str"
	"github.com/Luzifer/rconfig"
	log "github.com/sirupsen/logrus"
	"github.com/voxnoctem/uberspace_vmail/vptable"
	ldap "gopkg.in/ldap.v2"
)

var (
	cfg = struct {
		Create           bool   `flag:"create,c" default:"false" description:"Do not fail when database does not exist but create an empty database"`
		LDAPFilter       string `flag:"ldap-filter" env:"LDAP_FILTER" default:"(objectClass=uberspaceMailAccount)" description:"Query to find Uberspace mail accounts"`
		LDAPPassword     string `flag:"ldap-password" env:"LDAP_PASSWORD" default:"" description:"Password for the manager-dn"`
		LDAPManagerDN    string `flag:"ldap-manager-dn" env:"LDAP_MANAGER_DN" default:"" description:"DN to bind for querying the users" validate:"nonzero"`
		LDAPSearchBase   string `flag:"ldap-search-base" env:"LDAP_SEARCH_BASE" default:"" description:"DN with to search for users" validate:"nonzero"`
		LDAPServer       string `flag:"ldap-server" env:"LDAP_SERVER" default:"" description:"Address of the LDAP server (Format: ldap[s]://<host>[:<port>])" validate:"nonzero"`
		LogLevel         string `flag:"log-level" default:"info" description:"Log level for output (debug, info, warning, error, fatal)"`
		MailDomain       string `flag:"mail-domain" env:"MAIL_DOMAIN" default:"" description:"Domain to create addresses for: {uid}@{mail-domain}" validate:"nonzero"`
		MailPasswordFile string `flag:"mail-password-file,f" default:"~/passwd.cdb" description:"CDB file containing mail passwords"`
		VersionAndExit   bool   `flag:"version" default:"false" description:"Prints current version and exits"`
	}{}

	version = "dev"
)

func init() {
	if err := rconfig.ParseAndValidate(&cfg); err != nil {
		log.WithError(err).Fatal("Unable to parse commandline options")
	}

	if cfg.VersionAndExit {
		fmt.Printf("uberspace_vmail %s\n", version)
		os.Exit(0)
	}

	if l, err := log.ParseLevel(cfg.LogLevel); err != nil {
		log.WithError(err).Fatal("Invalid log-level")
	} else {
		log.SetLevel(l)
	}
}

func main() {
	vpt, err := vptable.LoadFromFile(cfg.MailPasswordFile)
	if err != nil {
		if !cfg.Create {
			log.WithError(err).Fatal("Unable to load passwd database")
		}
		vpt = vptable.New()
	}

	users, err := retrieveUsers()
	if err != nil {
		log.WithError(err).Fatal("Unable to retrieve users")
	}

	presentUsers := []string{}
	for uid, entry := range users {
		uidLogger := log.WithFields(log.Fields{"uid": uid})
		presentUsers = append(presentUsers, uid)

		oldEntry := vpt.Get(uid)
		if oldEntry != nil {
			attrs := []string{}
			if oldEntry.Directory != entry.Directory {
				attrs = append(attrs, "directory")
			}
			if oldEntry.Forwards != entry.Forwards {
				attrs = append(attrs, "forwards")
			}
			if oldEntry.Password != entry.Password {
				attrs = append(attrs, "password")
			}

			if len(attrs) == 0 {
				uidLogger.Debug("No change required")
				continue
			}

			uidLogger.WithFields(log.Fields{
				"fields": strings.Join(attrs, ", "),
			}).Info("Updated user")
		} else {
			uidLogger.Info("Added user")
			if err := makeMailDir(entry.Directory); err != nil {
				uidLogger.WithError(err).Error("Unable to create maildir for user")
			}
		}

		vpt.Upsert(uid, entry)
	}

	for _, u := range vpt.Users() {
		if !str.StringInSlice(u, presentUsers) {
			log.WithFields(log.Fields{"uid": u}).Info("Removed user")
			vpt.Remove(u)
		}
	}

	if err := vpt.SaveToFile(cfg.MailPasswordFile); err != nil {
		log.WithError(err).Fatal("Unable to save passwd database")
	}
}

func makeMailDir(dir string) error {
	if err := os.Mkdir(dir, 0700); err != nil {
		return err
	}
	for _, d := range []string{"tmp", "cur", "new"} {
		if err := os.Mkdir(path.Join(dir, d), 0700); err != nil {
			return err
		}
	}

	return nil
}

func retrieveUsers() (map[string]*vptable.VPEntry, error) {
	l, err := dialLDAP()
	if err != nil {
		return nil, err
	}
	defer l.Close()

	sreq := ldap.NewSearchRequest(
		cfg.LDAPSearchBase,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0, 0, false,
		cfg.LDAPFilter,
		[]string{"dn", "uid", "mailPassword", "mailDirectory", "mailForwards"},
		nil,
	)

	sres, err := l.Search(sreq)
	if err != nil {
		return nil, fmt.Errorf("Unable to search for users: %s", err)
	}

	result := map[string]*vptable.VPEntry{}
	for _, e := range sres.Entries {
		directory := e.GetAttributeValue("mailDirectory")
		if directory == "" {
			directory = fmt.Sprintf("./users/%s", e.GetAttributeValue("uid"))
		}

		result[e.GetAttributeValue("uid")] = &vptable.VPEntry{
			Password:  e.GetAttributeValue("mailPassword"),
			Directory: directory,
			Forwards:  e.GetAttributeValue("mailForwards"),
			Personal:  "",
			HardQuota: math.MaxUint64,
			SoftQuota: math.MaxUint64,
			MsgSize:   math.MaxUint64,
			MsgCount:  math.MaxUint64,
			ChangedAt: time.Now(),
		}
	}

	return result, err
}

func dialLDAP() (*ldap.Conn, error) {
	u, err := url.Parse(cfg.LDAPServer)
	if err != nil {
		return nil, err
	}

	host := strings.SplitN(u.Host, ":", 2)[0]
	port := u.Port()

	if port == "" {
		switch u.Scheme {
		case "ldap":
			port = "389"
		case "ldaps":
			port = "636"
		default:
			return nil, fmt.Errorf("Unsupported scheme %s", u.Scheme)
		}
	}

	l, err := ldap.Dial("tcp", fmt.Sprintf("%s:%s", host, port))
	if err != nil {
		return nil, fmt.Errorf("Unable to connect to LDAP: %s", err)
	}

	if err := l.Bind(cfg.LDAPManagerDN, cfg.LDAPPassword); err != nil {
		return nil, fmt.Errorf("Unable to authenticate with manager_dn: %s", err)
	}

	return l, err

}
