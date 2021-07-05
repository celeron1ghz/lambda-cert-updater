package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"

	"github.com/go-acme/lego/providers/dns/route53"
	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
)

type User struct {
	Email        string
	Registration *registration.Resource
	key          crypto.PrivateKey
}

func (u *User) GetEmail() string {
	return u.Email
}

func (u User) GetRegistration() *registration.Resource {
	return u.Registration
}

func (u *User) GetPrivateKey() crypto.PrivateKey {
	return u.key
}

func NewCertificate() *Certificate {
	return &Certificate{}
}

type Certificate struct {
}

func (c *Certificate) ObtainCertificate(mailAddress string, obtainDomains []string) (*certificate.Resource, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	if err != nil {
		return nil, err
	}

	config := lego.NewConfig(&User{Email: mailAddress, key: privateKey})
	config.CADirURL = "https://acme-staging-v02.api.letsencrypt.org/directory"
	config.Certificate.KeyType = certcrypto.EC384

	client, err := lego.NewClient(config)

	if err != nil {
		return nil, err
	}

	provider, err := route53.NewDNSProvider()

	if err != nil {
		return nil, err
	}

	client.Challenge.SetDNS01Provider(provider)

	_, err = client.Registration.Register(
		registration.RegisterOptions{TermsOfServiceAgreed: true},
	)

	if err != nil {
		return nil, err
	}

	certs, err := client.Certificate.Obtain(
		certificate.ObtainRequest{Domains: obtainDomains, Bundle: true},
	)

	if err != nil {
		return nil, err
	}

	return certs, nil
}
