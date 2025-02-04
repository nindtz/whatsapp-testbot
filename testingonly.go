package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"image"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"image/jpeg"
	"image/png"

	_ "github.com/mattn/go-sqlite3"
	"github.com/nfnt/resize"
	"go.mau.fi/whatsmeow"
	"go.mau.fi/whatsmeow/store/sqlstore"
	"go.mau.fi/whatsmeow/types"
	"go.mau.fi/whatsmeow/types/events"
	waLog "go.mau.fi/whatsmeow/util/log"
	"google.golang.org/protobuf/proto"

	waProto "go.mau.fi/whatsmeow/binary/proto"
)

var (
	client           *whatsmeow.Client
	allowedGroupJIDs = []string{
		"120363395779921603@g.us", // Replace with your actual group JIDs
		"120363399999999999@g.us",
		"120363388888888888@g.us",
	}
)

// Helper function to check if a group is in the allowed list
func isAllowedGroup(chatJID string) bool {
	for _, groupJID := range allowedGroupJIDs {
		if chatJID == groupJID {
			return true
		}
	}
	return false
}

func formatWithCommas(s string) string {
	n := len(s)
	if n <= 3 {
		return s
	}
	remainder := n % 3
	if remainder == 0 {
		remainder = 3
	}
	result := s[:remainder]
	for i := remainder; i < n; i += 3 {
		result += "." + s[i:i+3]
	}
	return result
}

// Handles incoming messages
func eventHandler(evt interface{}) {
	switch v := evt.(type) {
	case *events.Message:
		chatJID := v.Info.Chat.String()

		// Only process messages from the allowed groups
		if isAllowedGroup(chatJID) {
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

func sendImageMessageWithReply(chat types.JID, imgMsg *waProto.ImageMessage, quotedMsg *waProto.Message, msgID, senderID string) {
	if client == nil {
		log.Println("Client is not initialized")
		return
	}

	// Add ContextInfo to ImageMessage
	imgMsg.ContextInfo = &waProto.ContextInfo{
		StanzaID:      proto.String(msgID), // Corrected field name
		Participant:   proto.String(senderID),
		QuotedMessage: quotedMsg,
	}

	// Construct message payload
	message := &waProto.Message{
		ImageMessage: imgMsg,
	}

	// Send the message
	_, err := client.SendMessage(context.Background(), chat, message)
	if err != nil {
		log.Println("Failed to send image message:", err)
	} else {
		log.Println("Image message sent successfully!")
	}
}

// Ini commands di sebuah group
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

	// text = strings.ToLower(text) // Convert to lowercase for case-insensitive commands

	// Handle "time" command
	if strings.ToLower(text) == "time" {
		currentTime := time.Now().Format("15:04:05, Monday, Jan 2 2006")
		response := "🕒 Current time: " + currentTime

		// Send response to the group
		sendMessage(msg.Info.Chat, response)
	} else if strings.ToLower(text) == "halo" {
		// currentTime := time.Now().Format("15:04:05, Monday, Jan 2 2006")
		response := "Halo " + msg.Info.PushName

		// Send response to the group
		sendMessage(msg.Info.Chat, response)

	} else if strings.ToLower(text) == "date" {
		currentTime := time.Now().Format("15:04:05, Monday, Jan 2 2006")
		response := "🕒 Current time: " + currentTime

		// Construct message key from msg
		quotedMsg := msg.Message
		msgID := msg.Info.ID
		senderID := msg.Info.Sender.String()

		sendMessageWithReply(msg.Info.Chat, response, quotedMsg, msgID, senderID)

	} else if strings.HasPrefix(strings.ToLower(text), "cuaca") {
		// Create JSON payload
		words := strings.Split(text, " ")
		joinedWords := strings.Join(words[1:], " ")
		if len(joinedWords) > 1 {
			payload := map[string]string{
				"message": "Looking for weather in " + joinedWords,
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
			// Extracting the "reply" value
			reply := responseData["reply"]

			// Printing the final response
			finalResponse := "Sekarang " + reply // json.Unmarshal(body, &reply)
			quotedMsg := msg.Message
			msgID := msg.Info.ID
			senderID := msg.Info.Sender.String()

			sendMessageWithReply(msg.Info.Chat, finalResponse, quotedMsg, msgID, senderID)
		} else {
			fmt.Println("The string does not have a second word.")
		}

	} else if strings.HasPrefix(strings.ToLower(text), "hello") {
		// Create JSON payload
		words := strings.Split(text, " ")
		joinedWords := strings.Join(words[1:], " ")
		payload := map[string]string{
			"message": "The sender is " + joinedWords,
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
	} else if strings.HasPrefix(strings.ToLower(text), "donate") {
		// Create JSON payload
		words := strings.Split(text, " ")
		joinedWords := strings.Join(words[1:], " ")
		caption := "Donation " + joinedWords
		payload := map[string]string{
			"message": caption,
		}
		jsonData, err := json.Marshal(payload)
		if err != nil {
			log.Println("Error marshaling JSON:", err)
			return
		}

		// Make an HTTP POST request
		resp, err := http.Post("http://127.0.0.1:5002/", "application/json", bytes.NewBuffer(jsonData))
		if err != nil {
			log.Println("Error making POST request:", err)
			return
		}
		defer resp.Body.Close()

		// Reading the response body (image data)
		fileData, err := io.ReadAll(resp.Body)
		if err != nil {
			log.Println("Error reading response body:", err)
			return
		}
		// Create a temporary file
		tempFile, err := ioutil.TempFile("", "tempImage-*.png")
		if err != nil {
			log.Println("Error creating temporary file:", err)
			return
		}
		defer os.Remove(tempFile.Name()) // Clean up the temp file afterward

		// Write fileData to the temporary file
		if _, err := tempFile.Write(fileData); err != nil {
			log.Println("Error writing to temporary file:", err)
			return
		}
		if err := tempFile.Close(); err != nil {
			log.Println("Error closing temporary file:", err)
			return
		}

		// Use the tempFile.Name() as the filePath
		filePath := tempFile.Name()

		// Upload the image to WhatsApp server
		uploaded, err := uploadImage(fileData)
		if err != nil {
			log.Println("Error uploading image:", err)
			return
		}
		log.Println("Uploaded Image Response:", uploaded)
		// Convert base64 strings to []byte
		mediaKey, _ := base64.StdEncoding.DecodeString(uploaded["MediaKey"])
		fileEncSHA256, _ := base64.StdEncoding.DecodeString(uploaded["FileEncSHA256"])
		fileSHA256, _ := base64.StdEncoding.DecodeString(uploaded["FileSHA256"])

		thumbnail, err := generateJPEGThumbnail(filePath)
		if err != nil {
			log.Println("Failed to generate thumbnail:", err)
			thumbnail = nil // WhatsApp can still send without it
		}

		caption = "Here is your donation for Rp" + formatWithCommas(joinedWords) + ",-"
		// Creating WhatsApp ImageMessage
		imgMsg := &waProto.ImageMessage{
			Caption:       proto.String(caption),
			URL:           proto.String(uploaded["URL"]),
			DirectPath:    proto.String(uploaded["DirectPath"]),
			Mimetype:      proto.String("image/png"),
			MediaKey:      mediaKey,
			FileEncSHA256: fileEncSHA256,
			FileSHA256:    fileSHA256,
			FileLength:    proto.Uint64(uint64(len(fileData))),
			JPEGThumbnail: thumbnail,
		}

		// Send image message
		//sendImageMessage(msg.Info.Chat, imgMsg)

		sendImageMessageWithReply(msg.Info.Chat, imgMsg, msg.Message, msg.Info.ID, msg.Info.Sender.String())

	}

}

func sendImageMessage(jid types.JID, imgMsg *waProto.ImageMessage) {
	if client == nil {
		log.Println("Client is not initialized")
		return
	}

	// Construct message payload
	msg := &waProto.Message{
		ImageMessage: imgMsg,
	}

	_, err := client.SendMessage(context.Background(), jid, msg)
	if err != nil {
		log.Println("Failed to send message:", err)
	}
}

// Function to upload image to WhatsApp server
func uploadImage(fileData []byte) (map[string]string, error) {
	if len(fileData) == 0 {
		log.Println("Error: fileData is empty, cannot upload")
		return nil, errors.New("fileData is empty")
	}

	log.Println("Uploading image of size:", len(fileData))

	// Perform the upload
	uploaded, err := client.Upload(context.Background(), fileData, whatsmeow.MediaImage)
	if err != nil {
		log.Println("Error uploading image:", err)
		return nil, err
	}

	log.Println("Upload successful:", uploaded)

	return map[string]string{
		"URL":           uploaded.URL,
		"DirectPath":    uploaded.DirectPath,
		"MediaKey":      base64.StdEncoding.EncodeToString(uploaded.MediaKey),
		"FileEncSHA256": base64.StdEncoding.EncodeToString(uploaded.FileEncSHA256),
		"FileSHA256":    base64.StdEncoding.EncodeToString(uploaded.FileSHA256),
	}, nil
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
	allowedGroupJID := allowedGroupJIDs[0]
	groupJID := types.NewJID(strings.Split(allowedGroupJID, "@")[0], types.GroupServer)
	sendMessage(groupJID, message)

	// Send a success response
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"success", "message":"Sent successfully"}`))
}

func statusHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Only GET requests allowed", http.StatusMethodNotAllowed)
		return
	}

	// Send the message to WhatsApp
	// sendMessage(types.JID{User: allowedGroupJID}, message)
	allowedGroupJID := allowedGroupJIDs[0]
	groupJID := types.NewJID(strings.Split(allowedGroupJID, "@")[0], types.GroupServer)
	sendMessage(groupJID, "Bot is up and running")

	// Send a success response
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"success", "message":"Bot is up and running"}`))
}

func sendDirectMessageHandler(w http.ResponseWriter, r *http.Request) {
	// Extract user ID from URL
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 3 {
		http.Error(w, "Invalid request URL", http.StatusBadRequest)
		return
	}
	userID := parts[2] // Extract user ID from "/sendto/{user}"

	// Read JSON request body
	var requestData struct {
		Message string `json:"message"`
	}
	err := json.NewDecoder(r.Body).Decode(&requestData)
	if err != nil {
		http.Error(w, "Invalid JSON request", http.StatusBadRequest)
		return
	}

	// Construct the user's JID
	userJID := types.NewJID(userID, types.DefaultUserServer)

	// Send the message
	err = sendDirectMessage(userJID, requestData.Message)
	if err != nil {
		http.Error(w, "Failed to send message", http.StatusInternalServerError)
		return
	}

	// Response
	response := map[string]string{
		"status":  "success",
		"user":    userID,
		"message": requestData.Message,
	}
	json.NewEncoder(w).Encode(response)
}

// Send a direct message to a specific user
func sendDirectMessage(jid types.JID, message string) error {
	if client == nil {
		return fmt.Errorf("WhatsApp client is not initialized")
	}

	msg := &waProto.Message{
		Conversation: proto.String(message),
	}

	_, err := client.SendMessage(context.Background(), jid, msg)
	if err != nil {
		log.Println("Failed to send direct message:", err)
		return err
	}

	log.Println("Direct message sent successfully to:", jid.String())
	return nil
}

func sendMessageWithFileHandler(w http.ResponseWriter, r *http.Request) {
	// Extract user ID from URL
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 3 {
		http.Error(w, "Invalid request URL", http.StatusBadRequest)
		return
	}
	userID := parts[2] // Extract user ID from "/sendto/{user}"

	// ✅ Parse the "message" from form-data
	message := r.FormValue("message")
	if message == "" {
		http.Error(w, "Missing 'message' field", http.StatusBadRequest)
		return
	}

	// Parse the file
	file, header, err := r.FormFile("file1")
	if err != nil {
		http.Error(w, "File upload failed", http.StatusBadRequest)
		return
	}
	defer file.Close()

	// Generate a unique suffix with the original filename
	originalFilename := header.Filename
	timestamp := time.Now().Format("20060102")

	if err != nil {
		http.Error(w, "Failed to generate random suffix", http.StatusInternalServerError)
		return
	}
	newFilename := strings.TrimSuffix(originalFilename, filepath.Ext(originalFilename)) + "-" + timestamp + filepath.Ext(originalFilename)

	// Save the file locally
	tempFile, err := os.Create(filepath.Join(os.TempDir(), newFilename))
	if err != nil {
		http.Error(w, "Failed to save file", http.StatusInternalServerError)
		return
	}
	defer tempFile.Close()

	_, err = io.Copy(tempFile, file)
	if err != nil {
		http.Error(w, "Failed to save file", http.StatusInternalServerError)
		return
	}

	// Get the file path
	filePath := tempFile.Name()

	// Construct the user's JID
	userJID := types.NewJID(userID, types.DefaultUserServer)

	// Send the message with the file
	err = sendMessageWithFile(userJID, message, filePath)
	if err != nil {
		http.Error(w, "Failed to send message", http.StatusInternalServerError)
		return
	}

	// Response
	response := map[string]string{
		"status":  "success",
		"user":    userID,
		"message": message,
	}
	json.NewEncoder(w).Encode(response)
}

func generateJPEGThumbnail(filePath string) ([]byte, error) {
	// Open the image file
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %v", err)
	}
	defer file.Close()

	// Decode the image to identify its format
	img, imgType, err := image.Decode(file)
	if err != nil {
		return nil, fmt.Errorf("failed to decode image: %v", err)
	}
	log.Println("Image type:", imgType)

	// Reset file pointer to the beginning for re-decoding if necessary
	if _, err := file.Seek(0, 0); err != nil {
		return nil, fmt.Errorf("failed to seek file: %v", err)
	}

	// Convert PNG to JPEG if necessary
	if imgType == "png" {
		img, err = png.Decode(file)
		if err != nil {
			return nil, fmt.Errorf("failed to decode PNG: %v", err)
		}
	} else if imgType == "jpeg" {
		img, err = jpeg.Decode(file)
		if err != nil {
			return nil, fmt.Errorf("failed to decode JPEG: %v", err)
		}
	} else {
		return nil, fmt.Errorf("unsupported image type: %v", imgType)
	}

	// Resize the image to a thumbnail with a max width and height of 72 pixels
	thumbnail := resize.Thumbnail(72, 72, img, resize.Lanczos3)

	// Create a temporary file to store the resized image
	tempFilePath := filepath.Join(os.TempDir(), "thumbnail.jpg")
	out, err := os.Create(tempFilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to create temp file: %v", err)
	}
	defer out.Close()

	// Write the resized image to the temporary file
	err = jpeg.Encode(out, thumbnail, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to encode JPEG: %v", err)
	}

	// Read the temporary file back into a byte slice
	thumbnailBytes, err := os.ReadFile(tempFilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read thumbnail file: %v", err)
	}

	// Clean up the temporary file
	err = os.Remove(tempFilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to remove temp file: %v", err)
	}

	// Return the thumbnail as a byte slice
	return thumbnailBytes, nil
}

func detectFileType(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", fmt.Errorf("failed to open file: %v", err)
	}
	defer file.Close()

	buffer := make([]byte, 512)
	_, err = file.Read(buffer)
	if err != nil {
		return "", fmt.Errorf("failed to read file: %v", err)
	}

	mimeType := http.DetectContentType(buffer)
	return mimeType, nil
}

// sendMessageWithFile sends a message along with a media file
func sendMessageWithFile(jid types.JID, message, filePath string) error {
	if client == nil {
		return fmt.Errorf("WhatsApp client is not initialized")
	}

	// Read file into a byte slice
	fileData, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	// Detect file type from extension

	mimeType, err := detectFileType(filePath)
	if err != nil {
		return fmt.Errorf("failed to detect file type: %w", err)
	}

	var mediaType whatsmeow.MediaType
	var fileName string = filepath.Base(filePath)

	isPDF := mimeType == "application/pdf"
	if isPDF {
		mediaType = whatsmeow.MediaDocument
	} else {
		mediaType = whatsmeow.MediaImage // Default to image
	}

	// Upload file to WhatsApp
	uploaded, err := client.Upload(context.Background(), fileData, mediaType)
	if err != nil {
		return fmt.Errorf("failed to upload file: %w", err)
	}

	// Create WhatsApp message
	var msg *waProto.Message

	if isPDF {
		// Construct a DocumentMessage with a thumbnail (if needed)
		msg = &waProto.Message{
			DocumentMessage: &waProto.DocumentMessage{
				Caption:       proto.String(message),
				URL:           proto.String(uploaded.URL),
				Title:         proto.String(fileName),
				DirectPath:    proto.String(uploaded.DirectPath),
				Mimetype:      proto.String(mimeType),
				MediaKey:      uploaded.MediaKey,
				FileEncSHA256: uploaded.FileEncSHA256,
				FileSHA256:    uploaded.FileSHA256,
				FileLength:    proto.Uint64(uint64(len(fileData))),
				FileName:      proto.String(fileName),
				// Add other fields if necessary
			},
		}
	} else {
		// Generate a JPEG thumbnail for the image
		thumbnail, err := generateJPEGThumbnail(filePath)
		if err != nil {
			log.Println("Failed to generate thumbnail:", err)
			thumbnail = nil // WhatsApp can still send without it
		}
		// Construct an ImageMessage
		msg = &waProto.Message{
			ImageMessage: &waProto.ImageMessage{
				Caption:       proto.String(message),
				URL:           proto.String(uploaded.URL),
				DirectPath:    proto.String(uploaded.DirectPath),
				MediaKey:      uploaded.MediaKey,
				Mimetype:      proto.String(mimeType),
				FileEncSHA256: uploaded.FileEncSHA256,
				FileSHA256:    uploaded.FileSHA256,
				FileLength:    proto.Uint64(uint64(len(fileData))),
				JPEGThumbnail: thumbnail,
			},
		}
	}

	// Send the message
	_, err = client.SendMessage(context.Background(), jid, msg)
	if err != nil {
		return fmt.Errorf("failed to send message: %w", err)
	}

	fmt.Println("Message with file sent successfully to:", jid.String())
	return nil
}

// Start HTTP Server
func startHTTPServer() {
	http.HandleFunc("/send", httpHandler)
	http.HandleFunc("/status", statusHandler)
	http.HandleFunc("/sendto/", sendDirectMessageHandler)
	http.HandleFunc("/sendfile/", sendMessageWithFileHandler)
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
