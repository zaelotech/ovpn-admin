package main

import (
	"crypto/rand"
	"encoding/base32"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	qrcode "github.com/skip2/go-qrcode"
)

const (
	openvpnDir    = "/usr/local/etc/openvpn"
	oathUsersFile = openvpnDir + "/oath-users"
	otpSecretsDir = openvpnDir + "/otp-secrets"
)

// MFAData contém informações do MFA do usuário
type MFAData struct {
	Username   string `json:"username"`
	Secret     string `json:"secret"`
	QRCode     string `json:"qrCode"` // base64 PNG
	OTPAuthURL string `json:"otpAuthUrl"`
	Configured bool   `json:"configured"`
}

// generateTOTPSecret gera um secret TOTP aleatório em base32
func generateTOTPSecret() (string, error) {
	// Gerar 20 bytes aleatórios (160 bits)
	randomBytes := make([]byte, 20)
	_, err := rand.Read(randomBytes)
	if err != nil {
		return "", err
	}

	// Codificar em base32 sem padding
	secret := base32.StdEncoding.EncodeToString(randomBytes)
	secret = strings.TrimRight(secret, "=")

	return secret, nil
}

// createMFAForUser gera MFA (TOTP) para um usuário
func createMFAForUser(username string) (*MFAData, error) {
	// Verificar se usuário já tem MFA
	if hasMFA(username) {
		return getMFAData(username)
	}

	// Gerar secret
	secret, err := generateTOTPSecret()
	if err != nil {
		return nil, fmt.Errorf("failed to generate TOTP secret: %v", err)
	}

	// Criar diretório de secrets se não existe
	if err := os.MkdirAll(otpSecretsDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create otp-secrets dir: %v", err)
	}

	// Adicionar ao oath-users
	oathLine := fmt.Sprintf("HOTP/T30 %s - %s\n", username, secret)
	f, err := os.OpenFile(oathUsersFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to open oath-users: %v", err)
	}
	defer f.Close()

	if _, err := f.WriteString(oathLine); err != nil {
		return nil, fmt.Errorf("failed to write to oath-users: %v", err)
	}

	// Salvar backup do secret
	secretFile := fmt.Sprintf("%s/%s.txt", otpSecretsDir, username)
	secretContent := fmt.Sprintf("Usuario: %s\nSecret TOTP: %s\nCriado em: %s\n",
		username, secret, time.Now().Format("2006-01-02 15:04:05"))

	if err := os.WriteFile(secretFile, []byte(secretContent), 0600); err != nil {
		log.Warnf("Failed to write MFA backup for %s: %v", username, err)
	}

	// Gerar dados MFA
	return getMFAData(username)
}

// getMFAData obtém os dados MFA de um usuário (se existir)
func getMFAData(username string) (*MFAData, error) {
	secret, err := getSecretFromOathUsers(username)
	if err != nil {
		return nil, err
	}

	// Gerar OTP Auth URL
	otpAuthURL := fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s",
		*mfaIssuer, username, secret, *mfaIssuer)

	// Gerar QR Code
	qrPNG, err := qrcode.Encode(otpAuthURL, qrcode.Medium, 256)
	if err != nil {
		return nil, fmt.Errorf("failed to generate QR code: %v", err)
	}

	// Converter QR para base64
	qrBase64 := base64.StdEncoding.EncodeToString(qrPNG)

	return &MFAData{
		Username:   username,
		Secret:     secret,
		QRCode:     qrBase64,
		OTPAuthURL: otpAuthURL,
		Configured: true,
	}, nil
}

// hasMFA verifica se usuário tem MFA configurado
func hasMFA(username string) bool {
	content, err := os.ReadFile(oathUsersFile)
	if err != nil {
		return false
	}

	lines := strings.Split(string(content), "\n")
	searchPattern := fmt.Sprintf("HOTP/T30 %s ", username)

	for _, line := range lines {
		if strings.HasPrefix(line, searchPattern) {
			return true
		}
	}

	return false
}

// getSecretFromOathUsers extrai o secret de um usuário do arquivo oath-users
func getSecretFromOathUsers(username string) (string, error) {
	content, err := os.ReadFile(oathUsersFile)
	if err != nil {
		return "", fmt.Errorf("failed to read oath-users: %v", err)
	}

	lines := strings.Split(string(content), "\n")
	searchPattern := fmt.Sprintf("HOTP/T30 %s ", username)

	for _, line := range lines {
		if strings.HasPrefix(line, searchPattern) {
			// Formato: HOTP/T30 username - SECRET
			parts := strings.Fields(line)
			if len(parts) >= 4 {
				return parts[3], nil // Secret é o 4º campo
			}
		}
	}

	return "", fmt.Errorf("MFA not configured for user %s", username)
}
