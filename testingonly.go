package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"go.mau.fi/whatsmeow"
	"go.mau.fi/whatsmeow/store/sqlstore"
	"go.mau.fi/whatsmeow/types"
	"go.mau.fi/whatsmeow/types/events"
	waLog "go.mau.fi/whatsmeow/util/log"
	"google.golang.org/protobuf/proto"

	waProto "go.mau.fi/whatsmeow/binary/proto"
)

var (
	client          *whatsmeow.Client
	allowedGroupJID = "120363395779921603@g.us" // Replace with your actual group JID
)

// Handles incoming messages
func eventHandler(evt interface{}) {
	switch v := evt.(type) {
	case *events.Message:
		chatJID := v.Info.Chat.String()

		// Only process messages from the allowed group
		if chatJID == allowedGroupJID {
			processCommand(v)
		}
	}
}

// Send a message with a reply to a specific chat
func sendMessageWithReply(chat types.JID, response string, quotedMsg *waProto.Message, msgID, senderID string) {
	message := &waProto.Message{
		ExtendedTextMessage: &waProto.ExtendedTextMessage{
			Text: proto.String(response),
			ContextInfo: &waProto.ContextInfo{
				StanzaID:      proto.String(msgID), // Corrected field name
				Participant:   proto.String(senderID),
				QuotedMessage: quotedMsg,
			},
		},
	}

	// Send the message
	_, err := client.SendMessage(context.Background(), chat, message)
	if err != nil {
		log.Println("Error sending message:", err)
	} else {
		log.Println("Message sent successfully!")
	}
}

// Processes commands
func processCommand(msg *events.Message) {
	// Ensure client is initialized
	if client == nil {
		log.Println("Client is not initialized")
		return
	}

	// Get message text
	text := msg.Message.GetConversation()
	if text == "" {
		return
	}

	text = strings.ToLower(text) // Convert to lowercase for case-insensitive commands

	// Handle "time" command
	if text == "time" {
		currentTime := time.Now().Format("15:04:05, Monday, Jan 2 2006")
		response := "🕒 Current time: " + currentTime

		// Send response to the group
		sendMessage(msg.Info.Chat, response)
	} else if text == "date" {
		currentTime := time.Now().Format("15:04:05, Monday, Jan 2 2006")
		response := "🕒 Current time: " + currentTime

		// Construct message key from msg
		quotedMsg := msg.Message
		msgID := msg.Info.ID
		senderID := msg.Info.Sender.String()

		sendMessageWithReply(msg.Info.Chat, response, quotedMsg, msgID, senderID)
	} else if text == "hello" {
		// Create JSON payload
		payload := map[string]string{
			"message": "Hello from WhatsApp bot!",
		}
		jsonData, err := json.Marshal(payload)
		if err != nil {
			log.Println("Error marshaling JSON:", err)
			return
		}

		// Make an HTTP POST request
		resp, err := http.Post("http://127.0.0.1:5002", "application/json", bytes.NewBuffer(jsonData))
		if err != nil {
			log.Println("Error making POST request:", err)
			return
		}
		defer resp.Body.Close()

		// Reading the response body
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			log.Println("Error reading response body:", err)
			return
		}

		// Parsing the JSON response
		var responseData map[string]string
		err = json.Unmarshal(body, &responseData)
		if err != nil {
			log.Println("Error unmarshaling JSON:", err)
			return
		}

		// Extracting the "reply" value
		reply, exists := responseData["reply"]
		if !exists {
			log.Println("Key 'reply' not found in response")
			return
		}

		// Printing the final response
		finalResponse := "🌐 Response from server: " + reply // json.Unmarshal(body, &reply)
		sendMessage(msg.Info.Chat, finalResponse)
	}
}

// Sends a WhatsApp message
func sendMessage(jid types.JID, message string) {
	if client == nil {
		log.Println("Client is not initialized")
		return
	}

	// Construct message payload
	msg := &waProto.Message{
		Conversation: proto.String(message),
	}

	_, err := client.SendMessage(context.Background(), jid, msg)
	if err != nil {
		log.Println("Failed to send message:", err)
	}
}

// HTTP Handler to receive POST requests
func httpHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Only POST requests allowed", http.StatusMethodNotAllowed)
		return
	}

	// Read request body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Error reading request body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	// Parse JSON
	var requestData map[string]string
	err = json.Unmarshal(body, &requestData)
	if err != nil {
		http.Error(w, "Invalid JSON format", http.StatusBadRequest)
		return
	}

	// Extract message
	message, exists := requestData["message"]
	if !exists {
		http.Error(w, "Missing 'message' field", http.StatusBadRequest)
		return
	}

	// Send the message to WhatsApp
	// sendMessage(types.JID{User: allowedGroupJID}, message)

	groupJID := types.NewJID(strings.Split(allowedGroupJID, "@")[0], types.GroupServer)
	sendMessage(groupJID, message)

	// Send a success response
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"success", "message":"Sent successfully"}`))
}

// Start HTTP Server
func startHTTPServer() {
	http.HandleFunc("/send", httpHandler)
	serverAddr := ":6666"
	fmt.Println("HTTP Server started on", serverAddr)
	log.Fatal(http.ListenAndServe(serverAddr, nil))
}

func main() {
	dbLog := waLog.Stdout("Database", "DEBUG", true)
	container, err := sqlstore.New("sqlite3", "file:examplestore.db?_foreign_keys=on", dbLog)
	if err != nil {
		panic(err)
	}

	deviceStore, err := container.GetFirstDevice()
	if err != nil {
		panic(err)
	}

	clientLog := waLog.Stdout("Client", "DEBUG", true)
	client = whatsmeow.NewClient(deviceStore, clientLog)
	client.AddEventHandler(eventHandler)

	if client.Store.ID == nil {
		// No ID stored, new login
		qrChan, _ := client.GetQRChannel(context.Background())
		err = client.Connect()
		if err != nil {
			panic(err)
		}
		for evt := range qrChan {
			if evt.Event == "code" {
				fmt.Println("QR code:", evt.Code)
			} else {
				fmt.Println("Login event:", evt.Event)
			}
		}
	} else {
		// Already logged in, just connect
		err = client.Connect()
		if err != nil {
			panic(err)
		}
	}

	fmt.Println("Bot is running...")
	go startHTTPServer()
	// Listen for Ctrl+C
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	<-c

	client.Disconnect()
}
