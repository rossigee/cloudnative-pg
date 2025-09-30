/*
Copyright © contributors to CloudNativePG, established as
CloudNativePG a Series of LF Projects, LLC.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

SPDX-License-Identifier: Apache-2.0
*/

package controller

import (
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("selectWebhookCertificateNames", func() {
	var tempDir string

	BeforeEach(func() {
		var err error
		tempDir, err = os.MkdirTemp("", "webhook-cert-test")
		Expect(err).ToNot(HaveOccurred())
	})

	AfterEach(func() {
		err := os.RemoveAll(tempDir)
		Expect(err).ToNot(HaveOccurred())
	})

	Context("when both apiserver.crt and apiserver.key exist", func() {
		BeforeEach(func() {
			// Create both apiserver certificate files
			apiserverCertPath := filepath.Join(tempDir, "apiserver.crt")
			apiserverKeyPath := filepath.Join(tempDir, "apiserver.key")

			err := os.WriteFile(apiserverCertPath, []byte("cert content"), 0o600)
			Expect(err).ToNot(HaveOccurred())

			err = os.WriteFile(apiserverKeyPath, []byte("key content"), 0o600)
			Expect(err).ToNot(HaveOccurred())
		})

		It("should return apiserver certificate names", func() {
			certName, keyName, err := selectWebhookCertificateNames(tempDir)
			Expect(err).ToNot(HaveOccurred())
			Expect(certName).To(Equal("apiserver.crt"))
			Expect(keyName).To(Equal("apiserver.key"))
		})
	})

	Context("when both tls.crt and tls.key exist", func() {
		BeforeEach(func() {
			// Create both tls certificate files
			tlsCertPath := filepath.Join(tempDir, "tls.crt")
			tlsKeyPath := filepath.Join(tempDir, "tls.key")

			err := os.WriteFile(tlsCertPath, []byte("cert content"), 0o600)
			Expect(err).ToNot(HaveOccurred())

			err = os.WriteFile(tlsKeyPath, []byte("key content"), 0o600)
			Expect(err).ToNot(HaveOccurred())
		})

		It("should return tls certificate names", func() {
			certName, keyName, err := selectWebhookCertificateNames(tempDir)
			Expect(err).ToNot(HaveOccurred())
			Expect(certName).To(Equal("tls.crt"))
			Expect(keyName).To(Equal("tls.key"))
		})
	})

	Context("when both apiserver and tls files exist", func() {
		BeforeEach(func() {
			// Create both types of certificate files
			files := []string{"apiserver.crt", "apiserver.key", "tls.crt", "tls.key"}
			for _, file := range files {
				filePath := filepath.Join(tempDir, file)
				err := os.WriteFile(filePath, []byte("content"), 0o600)
				Expect(err).ToNot(HaveOccurred())
			}
		})

		It("should prefer apiserver files over tls files", func() {
			certName, keyName, err := selectWebhookCertificateNames(tempDir)
			Expect(err).ToNot(HaveOccurred())
			Expect(certName).To(Equal("apiserver.crt"))
			Expect(keyName).To(Equal("apiserver.key"))
		})
	})

	Context("error scenarios", func() {
		Context("when only apiserver.crt exists", func() {
			BeforeEach(func() {
				// Create only the certificate file, not the key
				apiserverCertPath := filepath.Join(tempDir, "apiserver.crt")
				err := os.WriteFile(apiserverCertPath, []byte("cert content"), 0o600)
				Expect(err).ToNot(HaveOccurred())
			})

			It("should return error for incomplete certificate pair", func() {
				certName, keyName, err := selectWebhookCertificateNames(tempDir)
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("no valid certificate pair found"))
				Expect(certName).To(Equal(""))
				Expect(keyName).To(Equal(""))
			})
		})

		Context("when only apiserver.key exists", func() {
			BeforeEach(func() {
				// Create only the key file, not the certificate
				apiserverKeyPath := filepath.Join(tempDir, "apiserver.key")
				err := os.WriteFile(apiserverKeyPath, []byte("key content"), 0o600)
				Expect(err).ToNot(HaveOccurred())
			})

			It("should return error for incomplete certificate pair", func() {
				certName, keyName, err := selectWebhookCertificateNames(tempDir)
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("no valid certificate pair found"))
				Expect(certName).To(Equal(""))
				Expect(keyName).To(Equal(""))
			})
		})

		Context("when only tls.crt exists", func() {
			BeforeEach(func() {
				// Create only the certificate file, not the key
				tlsCertPath := filepath.Join(tempDir, "tls.crt")
				err := os.WriteFile(tlsCertPath, []byte("cert content"), 0o600)
				Expect(err).ToNot(HaveOccurred())
			})

			It("should return error for incomplete certificate pair", func() {
				certName, keyName, err := selectWebhookCertificateNames(tempDir)
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("no valid certificate pair found"))
				Expect(certName).To(Equal(""))
				Expect(keyName).To(Equal(""))
			})
		})

		Context("when neither certificate pair exists", func() {
			It("should return error", func() {
				certName, keyName, err := selectWebhookCertificateNames(tempDir)
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("no valid certificate pair found"))
				Expect(certName).To(Equal(""))
				Expect(keyName).To(Equal(""))
			})
		})

		Context("when directory doesn't exist", func() {
			It("should return error", func() {
				nonExistentDir := filepath.Join(tempDir, "non-existent")
				certName, keyName, err := selectWebhookCertificateNames(nonExistentDir)
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("no valid certificate pair found"))
				Expect(certName).To(Equal(""))
				Expect(keyName).To(Equal(""))
			})
		})

		Context("when webhookCertDir is empty", func() {
			It("should check the default webhook cert directory and return error if no files exist", func() {
				certName, keyName, err := selectWebhookCertificateNames("")
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("no valid certificate pair found"))
				Expect(err.Error()).To(ContainSubstring("/run/secrets/cnpg.io/webhook"))
				Expect(certName).To(Equal(""))
				Expect(keyName).To(Equal(""))
			})
		})
	})
})
