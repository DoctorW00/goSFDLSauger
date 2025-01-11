package main

import (
	"fmt"
	"regexp"
	"strings"

	mqtt "github.com/eclipse/paho.mqtt.golang"
)

var mqttClient mqtt.Client

func initMqttClient(broker string, topic string) mqtt.Client {
	opts := mqtt.NewClientOptions()
	opts.AddBroker(broker)
	opts.SetClientID("goSFDLSauger")
	if mqtt_User != "" && mqtt_Pass != "" {
		opts.SetUsername(mqtt_User)
		opts.SetPassword(mqtt_Pass)
	}
	opts.SetDefaultPublishHandler(messageHandler)
	opts.OnConnectionLost = onConnectionLost

	mqttClient := mqtt.NewClient(opts)

	if token := mqttClient.Connect(); token.Wait() && token.Error() != nil {
		fmt.Printf("mqtt connect error: %s\n", token.Error())
		AddLoaderLog(fmt.Sprintf("mqtt connect error: %s\n", token.Error()))
		return nil
	}

	if token := mqttClient.Subscribe(topic, 0, nil); token.Wait() && token.Error() != nil {
		fmt.Printf("mqtt subscribe error: %s\n", token.Error())
		AddLoaderLog(fmt.Sprintf("mqtt subscribe error: %s\n", token.Error()))
		return nil
	}

	fmt.Printf("mqtt: successful subscription for topic: %s\n", topic)
	AddLoaderLog(fmt.Sprintf("mqtt: successful subscription for topic: %s\n", topic))

	return mqttClient
}

func onConnectionLost(client mqtt.Client, err error) {
	fmt.Printf("mqtt error: %s\n", err)
	AddLoaderLog(fmt.Sprintf("mqtt error: %s\n", err))
	mqttClient = nil
}

func sendMqttMessage(client mqtt.Client, topic string, message string) error {
	token := client.Publish(topic, 0, false, message)
	token.Wait()
	if token.Error() != nil {
		return fmt.Errorf("mqtt error sending message: %s", token.Error())
	}
	if DEBUG {
		fmt.Println("mqtt message:", message)
	}
	return nil
}

func messageHandler(client mqtt.Client, msg mqtt.Message) {
	if DEBUG {
		fmt.Printf("mqtt receiving topic: %s\n", msg.Topic())
		fmt.Printf("mqtt receiving message: %s\n", msg.Payload())
	}

	payloadString := string(msg.Payload())

	if msg.Topic() == "get" {
		if payloadString == "start" {
			if !isDownloadRunning {
				newMsg := "[mqtt] starting downloads ..."
				fmt.Println(newMsg)
				AddLoaderLog(newMsg)
				SendMQTTMsg(newMsg)
				go func() {
					if len(SFDL_Files) > 0 {
						sfdl_file := SFDL_Files[0]
						startLoaderFunctions(sfdl_file)
					}
				}()
			} else {
				newMsg := "[mqtt] error: unable to start (running download)"
				fmt.Println(newMsg)
				AddLoaderLog(newMsg)
				SendMQTTMsg(newMsg)
			}
		}
		if payloadString == "stop" {
			if isDownloadRunning {
				StopAllFTPDownloads()
				newMsg := "[mqtt] stopping all downloads!"
				fmt.Println(newMsg)
				AddLoaderLog(newMsg)
				SendMQTTMsg(newMsg)
			} else {
				newMsg := "[mqtt] error: there is no running download to stop!"
				fmt.Println(newMsg)
				AddLoaderLog(newMsg)
				SendMQTTMsg(newMsg)
			}
		}
	}
}

func isValidTopicFormat(topic string) bool {
	if strings.HasSuffix(topic, "/") {
		return false
	}
	validTopic := regexp.MustCompile(`^([a-zA-Z0-9\-_]+(/)?)*[a-zA-Z0-9\-_]+$`)
	return validTopic.MatchString(topic)
}

func SendMQTTMsg(message string, topicExtension ...string) error {
	if mqttClient == nil {
		return fmt.Errorf("mqtt error: client not connected")
	}

	sendTopic := mqtt_Topic

	if len(topicExtension) > 0 {
		sendTopic = fmt.Sprintf("%s/%s", sendTopic, strings.Join(topicExtension, "/"))
		if !isValidTopicFormat(sendTopic) {
			fmt.Println("mqtt error: not a valid topic format: ", sendTopic)
			sendTopic = mqtt_Topic
		}
	}

	err := sendMqttMessage(mqttClient, sendTopic, message)
	if err != nil {
		fmt.Println("mqtt: error sending message:", err)
		return err
	}
	return nil
}

func startMQTTClient() error {
	mqttClient = initMqttClient(mqtt_Broker, mqtt_Topic+"/get")
	if mqttClient == nil {
		return fmt.Errorf("mqtt error: unable to get client running")
	}
	return nil
}
