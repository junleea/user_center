package worker

import (
	"fmt"
	"net/smtp"
)

type MyEmail struct {
	Name string `json:"smtp_server_name"`
	SmtpHost     string  `json:"smtp_host"`
	SmtpUserName string `json:"smtp_user_name"`
	SmtpPassword string `json:"smtp_password"`
	SmtpPort     int `json:"smtp_port"`
	ImapPort     int  `json:"imap_port"`
}

func (e *MyEmail) Send(title, content string, toEmail []string) error {
	//捕获异常
	defer func() {
		if err := recover(); err != nil {
			fmt.Errorf("MyEmail send mail error: %s", err)
		}
	}()

	// 设置邮件头部
	header := make(map[string]string)
	header["From"] = e.SmtpUserName
	header["To"] = toEmail[0]

	header["Subject"] = title

	// 组装邮件消息
	message := ""
	for k, v := range header {
		message += fmt.Sprintf("%s: %s\r\n", k, v)
	}
	message += "\r\n" + content
	// 发送邮件
	err := smtp.SendMail(e.SmtpHost, smtp.PlainAuth("", e.SmtpUserName, e.SmtpPassword, "pop.qq.com"), e.SmtpUserName, toEmail, []byte(message))
	if err != nil {
		//log.Fatalf("smtp error: %s", err)
		fmt.Errorf("send mail error: %s", err)
	}

	return nil
}
