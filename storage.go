package main

import (
	"fmt"
	"io"
	"log"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/go-acme/lego/v4/certificate"
)

type Storage struct {
	s3         *s3.S3
	bucketName string
}

func NewStorage(bucketName string) *Storage {
	sess, _ := session.NewSession(
		&aws.Config{
			Region: aws.String("ap-northeast-1"),
		},
	)

	s3client := s3.New(sess)
	return &Storage{s3: s3client, bucketName: bucketName}
}

func (s *Storage) StoreCertificateFile(cert certificate.Resource) error {
	pairs := map[string][]byte{
		fmt.Sprintf("%s.crt", cert.Domain):        cert.Certificate,
		fmt.Sprintf("%s.issuer.crt", cert.Domain): cert.IssuerCertificate,
		fmt.Sprintf("%s.key", cert.Domain):        cert.PrivateKey,
	}

	for fileName, certContent := range pairs {
		log.Printf("Putting file to s3://%s/%s\n", s.bucketName, fileName)

		_, err := s.s3.PutObject(
			&s3.PutObjectInput{
				Bucket: aws.String(s.bucketName),
				Key:    aws.String(fileName),
				Body:   aws.ReadSeekCloser(strings.NewReader(string(certContent))),
			},
		)

		if err != nil {
			return err
		}
	}

	return nil
}

func (s *Storage) FetchCertificateFile(domain string) (io.Reader, error) {
	fileName := fmt.Sprintf("%s.crt", domain)

	ret, err := s.s3.GetObject(
		&s3.GetObjectInput{
			Bucket: aws.String(s.bucketName),
			Key:    aws.String(fileName),
		},
	)

	if err != nil {
		return nil, err
	}

	return ret.Body, nil
}
