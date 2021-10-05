package mailer

import (
	"html/template"
	"os"
)

func EmailVerificationContent(email string, token string) string {
	EmailVerificationUrl := os.Getenv("CLIENT_URL") + `/auth/verify/` + token + "?email=" + email
	return Template(template.HTML(
		`	<h4>Email Verification</h4>
			<p>Please click the following link to verify your email address:</p>
			<a style="text-align:center;" href="` + EmailVerificationUrl + `">` + EmailVerificationUrl + `</a>
		`))
}

func ForgotPasswordContent(email string, token string) string {
	EmailVerificationUrl := os.Getenv("CLIENT_URL") + `/auth/change-password/` + token + "?email=" + email
	return Template(template.HTML(
		`	<h4>Forgot password?</h4>
			<p>Please click the following link to change your password:</p>
			<a style="text-align:center;" href="` + EmailVerificationUrl + `">` + EmailVerificationUrl + `</a>
		`))
}

func EmailVerificationSend(email string, token string) {
	Send(email, "Email Verification", EmailVerificationContent(email, token))
}

func ForgotPasswordSend(email string, token string) {
	Send(email, "Forgot Password?", ForgotPasswordContent(email, token))
}
