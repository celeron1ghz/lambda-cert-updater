package main

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"io/ioutil"
	"log"
	"os"
	"strings"
	"time"
)

func main() {
	mailAddress := os.Getenv("CERT_UPDATER_MAIL_ADDRESS")
	obtainDomains := strings.Split(os.Getenv("CERT_UPDATER_OBTAIN_DOMAINS"), ",")
	certificateStoreBucket := os.Getenv("CERT_UPDATER_CERTIFICATE_BUCKET")

	storageClient := NewStorage(certificateStoreBucket)
	refreshDomains := []string{}

	for _, domain := range obtainDomains {
		existCert, err := storageClient.FetchCertificateFile(domain)

		if err != nil {
			refreshDomains = append(refreshDomains, domain)

			log.Printf("[%s] Brand new domain. Certificate will create...\n", domain)
		} else {
			remain, err := GetCertificateRemainDay(existCert)

			if err != nil {
				log.Fatalf("[%s] Parsing certificate failed: %s", domain, err)
			} else {
				if remain <= 30 {
					refreshDomains = append(refreshDomains, domain)

					log.Printf("[%s] Remain %d days. Certificate will refresh...\n", domain, remain)
				} else {
					log.Printf("[%s] Remain %d days. Skip...\n", domain, remain)
				}
			}
		}
	}

	certClient := NewCertificate()

	for _, domain := range refreshDomains {
		cert, err := certClient.ObtainCertificate(mailAddress, []string{domain})

		if err != nil {
			log.Fatal("obtain certificate failed: ", err)
		}

		err = storageClient.StoreCertificateFile(*cert)

		if err != nil {
			log.Fatal("store certificate failed: ", err)
		}
	}
}

func GetCertificateRemainDay(certReader io.Reader) (int, error) {
	b, err := ioutil.ReadAll(certReader)

	if err != nil {
		return 0, err
	}

	p, _ := pem.Decode(b)

	if p == nil {
		return 0, errors.New("Certificate contents is empty or invalid")
	}

	cert, err := x509.ParseCertificate(p.Bytes)

	if err != nil {
		return 0, err
	}

	remain := time.Until(cert.NotAfter)
	remainDays := int(remain.Hours() / 24)
	return remainDays, nil
}
