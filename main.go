package main

import (
	"crypto/tls"
	"github.com/Snawoot/socks5-server/pkg/ldapAuth"
	"github.com/Snawoot/socks5-server/pkg/tls2"
	"github.com/armon/go-socks5"
	"github.com/caarlos0/env"
	"log"
	"net"
	"os"
	"strings"
)

type params struct {
	User      string `env:"PROXY_USER" envDefault:""`
	Password  string `env:"PROXY_PASSWORD" envDefault:""`
	Address   string `env:"PROXY_ADDRESS" envDefault:""`
	Port      string `env:"PROXY_PORT" envDefault:"1080"`
	TLSCert   string `env:"PROXY_TLS_CERT" envDefault:""`
	TLSKey    string `env:"PROXY_TLS_KEY" envDefault:""`
	TLSCACert string `env:"PROXY_TLS_CACERT" envDefault:""`

	LdapUser     string `env:"PROXY_LDAP_USER" envDefault:""`
	LdapPassword string `env:"PROXY_LDAP_PASSWORD" envDefault:""`
	LdapBaseDB   string `env:"PROXY_LDAP_BASEDN" envDefault:""`
	LdapHost     string `env:"PROXY_LDAP_HOST" envDefault:""`
	LdapEnable   string `env:"PROXY_LDAP_ENABLE" envDefault:""`
}

func main() {
	// Working with app params
	cfg := params{}
	err := env.Parse(&cfg)
	if err != nil {
		log.Printf("%+v\n", err)
	}
	ldapAuth.InitDefaultpPool(cfg.LdapHost)
	ldap := ldapAuth.NewLdap(cfg.LdapUser, cfg.LdapPassword, cfg.LdapBaseDB, cfg.LdapHost)

	//Initialize socks5 config
	socsk5conf := &socks5.Config{
		Logger: log.New(os.Stdout, "", log.LstdFlags),
	}
	switch {
	case strings.ToLower(cfg.LdapEnable) == "true":
		socsk5conf.AuthMethods = []socks5.Authenticator{ldap}
	case cfg.User+cfg.Password != "":
		creds := socks5.StaticCredentials{
			cfg.User: cfg.Password,
		}
		cator := socks5.UserPassAuthenticator{Credentials: creds}
		socsk5conf.AuthMethods = []socks5.Authenticator{cator}
		socsk5conf.AuthMethods = []socks5.Authenticator{cator}
	}

	server, err := socks5.New(socsk5conf)
	if err != nil {
		log.Fatal(err)
	}

	var listener net.Listener
	listenAddr := net.JoinHostPort(cfg.Address, cfg.Port)

	if cfg.TLSCert != "" {
		if cfg.TLSKey == "" {
			log.Fatal("PROXY_TLS_KEY is not specified")
		}
		tlsCfg, err := tls2.MakeServerTLSConfig(cfg.TLSCert, cfg.TLSKey, cfg.TLSCACert)
		if err != nil {
			log.Fatal(err)
		}
		listener, err = tls.Listen("tcp", listenAddr, tlsCfg)
		if err != nil {
			log.Fatal(err)
		}
	} else {
		listener, err = net.Listen("tcp", listenAddr)
		if err != nil {
			log.Fatal(err)
		}
	}

	log.Printf("Proxy service is listening on port %s\n", cfg.Port)
	if err := server.Serve(listener); err != nil {
		log.Fatal(err)
	}
}
