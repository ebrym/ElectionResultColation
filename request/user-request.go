package request

type UsernameUpdate struct {
	Username string `json:"username"`
}

type CodeVerificationReq struct {
	Code string `json: "code"`
	Type string `json" "type"`
}

type PasswordResetReq struct {
	Password   string `json: "password"`
	PasswordRe string `json: "password_re"`
	Code       string `json: "code"`
}
