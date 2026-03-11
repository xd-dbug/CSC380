package main

import (
	"context"
	"encoding/json"
	"net/mail"

	"github.com/segmentio/kafka-go"
)

type Event string

const (
	PasswordChanged Event = "PasswordChanged"
	OfferCreated    Event = "OfferCreated"
	OfferAccepted   Event = "OfferAccepted"
	OfferRejected   Event = "OfferRejected"
)

type EmailNotification struct {
	EventType  Event         `json:"eventType"`
	Recipient1 mail.Address  `json:"recipient1"`
	Recipient2 *mail.Address `json:"recipient2"`
	Subject    string        `json:"subject"`
	Body       string        `json:"body"`
}

func publishEmailNotification(notification EmailNotification) error {
	jsonByte, err := json.Marshal(notification)
	if err != nil {
		return err
	}

	err = kafkaWriter.WriteMessages(context.Background(),
		kafka.Message{
			Value: jsonByte,
		})
	if err != nil {
		return err
	}

	return nil
}
