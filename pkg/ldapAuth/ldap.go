package ldapAuth

import (
	"fmt"
	"github.com/armon/go-socks5"
	"github.com/go-ldap/ldap"
	"io"
	"log"
	"reflect"
)

type LdapAuth struct {
	BaseDN   string
	User     string
	Password string
	Host     string
}

func NewLdap(user, password, baseDN, host string) *LdapAuth {

	return &LdapAuth{
		BaseDN:   baseDN,
		User:     user,
		Password: password,
		Host:     host,
	}
}

const (
	NoAuth          = uint8(0)
	noAcceptable    = uint8(255)
	UserPassAuth    = uint8(2)
	userAuthVersion = uint8(1)
	authSuccess     = uint8(0)
	authFailure     = uint8(1)
	socks5Version   = uint8(5)
)

func (l *LdapAuth) Authenticate(reader io.Reader, writer io.Writer) (*socks5.AuthContext, error) {

	if _, err := writer.Write([]byte{socks5Version, UserPassAuth}); err != nil {
		return nil, err
	}

	// Get the version and username length
	header := []byte{0, 0}
	if _, err := io.ReadAtLeast(reader, header, 2); err != nil {
		return nil, err
	}

	// Ensure we are compatible
	if header[0] != userAuthVersion {
		return nil, fmt.Errorf("Unsupported auth version: %v", header[0])
	}

	// Get the user name
	userLen := int(header[1])
	user := make([]byte, userLen)
	if _, err := io.ReadAtLeast(reader, user, userLen); err != nil {
		return nil, err
	}

	// Get the password length
	if _, err := reader.Read(header[:1]); err != nil {
		return nil, err
	}

	// Get the password
	passLen := int(header[0])
	pass := make([]byte, passLen)
	if _, err := io.ReadAtLeast(reader, pass, passLen); err != nil {
		return nil, err
	}

	// Verify the password
	conn, err := LdapPool.Acquire(l.User, l.Password)
	defer LdapPool.Release(conn)
	if err != nil {
		return nil, err
	}

	ldapEntry, exist := l.userExist(string(user))
	if !exist {
		log.Printf("Cannot find user: %s", user)
		if _, err := writer.Write([]byte{userAuthVersion, authFailure}); err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("Cannot find user: %s", user)
	}

	if err := conn.Bind(ldapEntry.DN, string(pass)); err != nil {
		log.Printf("User %s password is invalid", user)
		if _, err := writer.Write([]byte{userAuthVersion, authFailure}); err != nil {
			return nil, err
		}
	}

	if _, err := writer.Write([]byte{userAuthVersion, authSuccess}); err != nil {
		return nil, err
	}

	// Done
	return &socks5.AuthContext{UserPassAuth, map[string]string{"Username": string(user)}}, nil
}

func (l *LdapAuth) GetCode() uint8 {
	return UserPassAuth
}

func (l *LdapAuth) userExist(uid string) (ldapEntry *ldap.Entry, exist bool) {

	searchRequest := ldap.NewSearchRequest(
		l.BaseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		// LDAP 搜索时的匹配模式
		fmt.Sprintf("(&(objectClass=person)(uid=%s))", uid),
		// 这里是查询返回的属性，
		[]string{},
		nil,
	)
	// 返回数组
	conn, err := LdapPool.Acquire(l.User, l.Password)
	defer LdapPool.Release(conn)
	if err != nil {
		return nil, false
	}

	sr, err := conn.Search(searchRequest)
	if err != nil {
		log.Println(err)
		return nil, false
	}

	if !reflect.DeepEqual(sr, ldap.SearchResult{}) {
		if len(sr.Entries) > 0 {
			return sr.Entries[0], true
		}
	}

	return

}
