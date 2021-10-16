package mailer

import (
	"bytes"
	"crypto/tls"
	"html/template"
	"log"
	"os"
	"strconv"

	"gopkg.in/gomail.v2"
)

type DialerOptions struct {
	CONFIG_SMTP_HOST     string
	CONFIG_SMTP_PORT     int
	CONFIG_AUTH_EMAIL    string
	CONFIG_AUTH_PASSWORD string
}

type TemplateData struct {
	InnerHtml template.HTML
}

/*
   |--------------------------------------------------------------------------
   | Template
   |--------------------------------------------------------------------------
*/
func Template(innerHTML template.HTML) string {
	var data TemplateData
	data.InnerHtml = innerHTML

	t, err := template.ParseFiles(os.Getenv("MAILER_TEMPLATE_PATH"))
	if err != nil {
		log.Fatal(err)
	}

	buffer := new(bytes.Buffer)

	if err = t.Execute(buffer, data); err != nil {
		log.Fatal(err)
	}

	return buffer.String()
}

/*
   |--------------------------------------------------------------------------
   | Send
   |--------------------------------------------------------------------------
*/
func Send(toEmail string, subject string, message string) {
	MAILER_FROM := os.Getenv("MAILER_FROM")
	MAILER_EMAIL := os.Getenv("MAILER_EMAIL")
	MAILER_PASSWORD := os.Getenv("MAILER_PASSWORD")
	MAILER_PORT, _ := strconv.Atoi(os.Getenv("MAILER_PORT"))
	MAILER_HOST := os.Getenv("MAILER_HOST")

	options := DialerOptions{
		CONFIG_SMTP_HOST:     MAILER_HOST,
		CONFIG_SMTP_PORT:     MAILER_PORT,
		CONFIG_AUTH_EMAIL:    MAILER_EMAIL,
		CONFIG_AUTH_PASSWORD: MAILER_PASSWORD,
	}

	process(MAILER_FROM, toEmail, message, subject, options)
}

/*
   |--------------------------------------------------------------------------
   | Finish
   |--------------------------------------------------------------------------
*/
func process(fromEmail string, toEmail string, message string, subject string, options DialerOptions) {
	mailer := gomail.NewMessage()

	mailer.SetHeader("From", fromEmail)
	mailer.SetHeader("To", toEmail)
	mailer.SetHeader("Subject", subject)
	mailer.SetBody("text/html", message)

	dialer := gomail.NewDialer(
		options.CONFIG_SMTP_HOST,
		options.CONFIG_SMTP_PORT,
		options.CONFIG_AUTH_EMAIL,
		options.CONFIG_AUTH_PASSWORD,
	)
	dialer.TLSConfig = &tls.Config{InsecureSkipVerify: true}

	err := dialer.DialAndSend(mailer)
	if err != nil {
		log.Fatal(err.Error())
	}
}
