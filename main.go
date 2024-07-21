package main

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"os"
	"runtime"
	"strings"
	"time"

	"software.sslmate.com/src/go-pkcs12"
)

func main() {
	isletimSistemi := runtime.GOOS
	okuyucu := bufio.NewReader(os.Stdin)

	fmt.Print("Kurum Adı: ")
	kurumAdi, _ := okuyucu.ReadString('\n')
	kurumAdi = strings.TrimSpace(kurumAdi)

	fmt.Print("Kişi Adı: ")
	kisiAdi, _ := okuyucu.ReadString('\n')
	kisiAdi = strings.TrimSpace(kisiAdi)

	fmt.Print("Versiyon Sürümü: ")
	versiyon, _ := okuyucu.ReadString('\n')
	versiyon = strings.TrimSpace(versiyon)

	fmt.Print("Şifre (Opsiyonel): ")
	sifre, _ := okuyucu.ReadString('\n')
	sifre = strings.TrimSpace(sifre)

	fmt.Print("Dosya Adı: ")
	dosyaAdi, _ := okuyucu.ReadString('\n')
	dosyaAdi = strings.TrimSpace(dosyaAdi)

	fmt.Print("Kaydedilecek Dizini Girin: ")
	dizinYolu, _ := okuyucu.ReadString('\n')
	dizinYolu = strings.TrimSpace(dizinYolu)

	if isletimSistemi == "windows" {
		pfxSertifikaOlusturVeKaydet(kurumAdi, kisiAdi, versiyon, sifre, dizinYolu, dosyaAdi)
	} else {
		pemSertifikaOlusturVeKaydet(kurumAdi, kisiAdi, versiyon, dizinYolu, dosyaAdi)
	}
}

func pfxSertifikaOlusturVeKaydet(kurumAdi, kisiAdi, versiyon, sifre, dizinYolu, dosyaAdi string) {
	ozelAnahtar, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("Özel anahtar oluşturma başarısız: %v", err)
	}

	sablon := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{kurumAdi},
			CommonName:   kisiAdi,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &sablon, &sablon, &ozelAnahtar.PublicKey, ozelAnahtar)
	_ = derBytes
	if err != nil {
		log.Fatalf("Sertifika oluşturma başarısız: %v", err)
	}

	pfxData, err := pkcs12.Encode(rand.Reader, ozelAnahtar, &sablon, []*x509.Certificate{&sablon}, sifre)
	if err != nil {
		log.Fatalf("PFX kodlama başarısız: %v", err)
	}

	dosyaYolu := fmt.Sprintf("%s/%s.pfx", dizinYolu, dosyaAdi)
	err = os.WriteFile(dosyaYolu, pfxData, 0644)
	if err != nil {
		log.Fatalf("Dosya kaydetme başarısız: %v", err)
	}

	fmt.Printf("PFX sertifikası %s dizinine %s adıyla kaydedildi.\n", dizinYolu, dosyaAdi)
}

func pemSertifikaOlusturVeKaydet(kurumAdi, kisiAdi, versiyon, dizinYolu, dosyaAdi string) {
	ozelAnahtar, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("Özel anahtar oluşturma başarısız: %v", err)
	}

	sablon := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{kurumAdi},
			CommonName:   kisiAdi,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &sablon, &sablon, &ozelAnahtar.PublicKey, ozelAnahtar)
	if err != nil {
		log.Fatalf("Sertifika oluşturma başarısız: %v", err)
	}

	sertifikaPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	ozelAnahtarPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(ozelAnahtar)})

	dosyaYolu := fmt.Sprintf("%s/%s.pem", dizinYolu, dosyaAdi)
	err = os.WriteFile(dosyaYolu, append(sertifikaPEM, ozelAnahtarPEM...), 0644)
	if err != nil {
		log.Fatalf("Dosya kaydetme başarısız: %v", err)
	}

	fmt.Printf("PEM sertifikası %s dizinine %s adıyla kaydedildi.\n", dizinYolu, dosyaAdi)
}
