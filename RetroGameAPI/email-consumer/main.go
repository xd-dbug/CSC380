package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/mail"
	"os"
	"strconv"

	"github.com/segmentio/kafka-go"
	gomail "gopkg.in/mail.v2"
)

var kafkaReader *kafka.Reader

var (
	SMTPHost     string
	SMTPPort     int
	SMTPUser     string
	SMTPPassword string
)

type Event string

type EmailNotification struct {
	EventType  Event         `json:"eventType"`
	Recipient1 mail.Address  `json:"recipient1"`
	Recipient2 *mail.Address `json:"recipient2"`
	Subject    string        `json:"subject"`
	Body       string        `json:"body"`
}

func sendEmail(recipient mail.Address, subject string, body string) {
	m := gomail.NewMessage()
	m.SetHeader("From", SMTPUser)
	m.SetHeader("To", recipient.String())
	m.SetHeader("Subject", subject)
	m.SetBody("text/html", body)

	d := gomail.NewDialer(SMTPHost, SMTPPort, SMTPUser, SMTPPassword)

	// Send the email
	if err := d.DialAndSend(m); err != nil {
		fmt.Printf("[ERROR] Could not send email to %s: %s\n", recipient.Address, err)
	} else {
		fmt.Printf("[INFO] Email sent successfully to %s\n", recipient.Address)
	}
}

func main() {
	kafkaBroker := os.Getenv("KAFKA_BROKER")
	SMTPHost = os.Getenv("SMTP_HOST")
	portStr := os.Getenv("SMTP_PORT")
	SMTPUser = os.Getenv("SMTP_USER")
	SMTPPassword = os.Getenv("SMTP_PASSWORD")

	if kafkaBroker == "" {
		kafkaBroker = "broker:19092"
	}
	if SMTPHost == "" {
		SMTPHost = "host"
	}
	if portStr == "" {
		portStr = "25"
	}
	if SMTPUser == "" {
		SMTPUser = "user"
	}
	if SMTPPassword == "" {
		SMTPPassword = "password"
	}

	var err error
	SMTPPort, err = strconv.Atoi(portStr)
	if err != nil {
		log.Printf("Invalid SMTP_PORT, defaulting to 25: %v", err)
		SMTPPort = 25
	}

	kafkaReader = kafka.NewReader(kafka.ReaderConfig{
		Brokers:  []string{kafkaBroker},
		GroupID:  "consumer-group-id",
		Topic:    "notificationEvents",
		MaxBytes: 10e6,
	})

	defer func(kafkaReader *kafka.Reader) {
		err := kafkaReader.Close()
		if err != nil {
			log.Fatal(err)
		}
	}(kafkaReader)

	for {
		msg, err := kafkaReader.ReadMessage(context.Background())
		if err != nil {
			fmt.Printf("[ERROR] %s\n", err)
			continue
		}

		var notification EmailNotification

		err = json.Unmarshal(msg.Value, &notification)
		if err != nil {
			fmt.Printf("[ERROR] %s\n", err)
			continue
		}

		sendEmail(notification.Recipient1, notification.Subject, notification.Body)

		if notification.Recipient2 != nil {
			sendEmail(*notification.Recipient2, notification.Subject, notification.Body)
		}

	}

}
