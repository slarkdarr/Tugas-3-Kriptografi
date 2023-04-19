package main

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/slarkdarr/Tugas-2-Kriptografi/internal"
	"github.com/slarkdarr/Tugas-2-Kriptografi/internal/impl"
	"golang.org/x/exp/slices"
)

// messageBody represents data about the body of a message.
type Message struct {
  Key string `json:"key"`
  Body string `json:"body"`
}

type Key struct {
  KeyString string `json:"key"`
}

type CipherMessage struct {
  EncryptedMessage string
  Cipher internal.Cipher
}

var keyMessages map[string][]CipherMessage

func EncryptMessage(cipher internal.Cipher, ciphertext string) string {
  enc := cipher.Encrypt(ciphertext)
  return enc
}

func DecryptMessage(cipher internal.Cipher, plaintext string) string {
  dec := cipher.Decrypt(plaintext)
  return dec
}

// encrypt function encrypts a message from JSON received in the request body.
func encrypt(c *gin.Context) {
  if c.Request.URL.Path != "/encrypt" {
    c.IndentedJSON(http.StatusNotFound, "404 not found.")
    return
  }

  if c.Request.Method != "POST" {
    c.IndentedJSON(http.StatusMethodNotAllowed, "Method is not supported.")
    return
  }

  var message Message

  // Call BindJSON to bind the received JSON to
  // body.
  if err := c.BindJSON(&message); err != nil {
    c.IndentedJSON(http.StatusBadRequest, err.Error())
    return
  }

  if message.Key == "" {
    c.IndentedJSON(http.StatusBadRequest, "Please provide a key")
    return
  }

  var res string
  var cipher internal.Cipher
  _, found := keyMessages[message.Key]
  if found {
    idx := slices.IndexFunc(keyMessages[message.Key], func(c CipherMessage) bool { return c.EncryptedMessage == message.Body })
    if idx != -1 {
      cipher = keyMessages[message.Key][idx].Cipher
      res = EncryptMessage(cipher, message.Body)
    } else {
      cipher = impl.NewCipher(message.Key)
      res = EncryptMessage(cipher, message.Body)
    }
  } else {
    cipher = impl.NewCipher(message.Key)
    res = EncryptMessage(cipher, message.Body)
  }

  cipherMessage := CipherMessage{
    EncryptedMessage: res,
    Cipher: cipher,
  }

  keyMessages[message.Key] = append(keyMessages[message.Key], cipherMessage)

  c.Data(http.StatusOK, "plain/text", []byte(res))
}

// decrypt function decrypts a message from JSON received in the request body.
func decrypt(c *gin.Context) {
  if c.Request.URL.Path != "/decrypt" {
    c.IndentedJSON(http.StatusNotFound, "404 not found.")
    return
  }

  if c.Request.Method != "POST" {
    c.IndentedJSON(http.StatusNotFound, "Method is not supported.")
    return
  }

  var message Message

  // Call BindJSON to bind the received JSON to
  // body.
  if err := c.BindJSON(&message); err != nil {
    c.IndentedJSON(http.StatusBadRequest, err.Error())
    return
  }

  if message.Key == "" {
    c.IndentedJSON(http.StatusBadRequest, "Please provide a key")
    return
  }

  var res string
  var cipher internal.Cipher
  _, found := keyMessages[message.Key]
  if found {
    idx := slices.IndexFunc(keyMessages[message.Key], func(c CipherMessage) bool { return c.EncryptedMessage == message.Body })
    if idx != -1 {
      cipher = keyMessages[message.Key][idx].Cipher
      res = DecryptMessage(cipher, message.Body)
    } else {
      cipher = impl.NewCipher(message.Key)
      res = DecryptMessage(cipher, message.Body)
    }
  } else {
    cipher = impl.NewCipher(message.Key)
    res = DecryptMessage(cipher, message.Body)
  }

  c.Data(http.StatusOK, "plain/text", []byte(res))
}

func handleRequests() {
  router := gin.Default()
	router.POST("/encrypt", encrypt)
  router.POST("/decrypt", decrypt)

	fmt.Println("Starting server at port 8080...")
	router.Run("localhost:8080")
}

func main() {
  keyMessages = make(map[string][]CipherMessage)
  handleRequests()
}
