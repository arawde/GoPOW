/*
Implements the solution to assignment 1 for UBC CS 416 2017 W2.

Usage:
$ go run client.go [local UDP ip:port] [local TCP ip:port] [aserver UDP ip:port]

Example:
$ go run client.go 127.0.0.1:2020 127.0.0.1:3030 127.0.0.1:7070

*/

package main

import (
  "crypto/md5"
  "encoding/binary"
  "encoding/hex"
  "encoding/json"
  "fmt"
  "math/rand"
  "net"
  "os"
  "strings"
)

/////////// Msgs used by both auth and fortune servers:

// An error message from the server.
type ErrMessage struct {
  Error string
}

/////////// Auth server msgs:

// Message containing a nonce from auth-server.
type NonceMessage struct {
  Nonce string
  N     int64 // PoW difficulty: number of zeroes expected at end of md5(nonce+secret)
}

// Message containing an the secret value from client to auth-server.
type SecretMessage struct {
  Secret string
}

// Message with details for contacting the fortune-server.
type FortuneInfoMessage struct {
  FortuneServer string // TCP ip:port for contacting the fserver
  FortuneNonce  int64
}

/////////// Fortune server msgs:

// Message requesting a fortune from the fortune-server.
type FortuneReqMessage struct {
  FortuneNonce int64
}

// Response from the fortune-server containing the fortune.
type FortuneMessage struct {
  Fortune string
  Rank    int64 // Rank of this client solution
}

// Main workhorse method.
func main() {
  // Read command args
  localUDPAddr, err := net.ResolveUDPAddr("udp", os.Args[1])
  localTCPAddr, err := net.ResolveTCPAddr("tcp", os.Args[2])
  aServerAddr, err := net.ResolveUDPAddr("udp", os.Args[3])
  if err != nil {
    fmt.Printf("Error resolving argument addresses: %v\n", err)
  }
  // Use json.Marshal json.Unmarshal for encoding/decoding to servers

  // Connect to server via UDP
  // https://stackoverflow.com/questions/26028700/write-to-client-udp-socket-in-go
  uconnection, err := net.DialUDP("udp", localUDPAddr, aServerAddr)
  if err != nil {
    fmt.Printf("Error connecting to aServer: %v\n", err)
  }
  defer uconnection.Close()

  // Send arbitrary message
  uconnection.Write([]byte("Hi"))
  message := make([]byte, 1024)

  length, err := uconnection.Read(message)
  if err != nil {
    fmt.Printf("Error reading response on connection: %v\n", err)
  }

  var nonceMessage NonceMessage
  // https://stackoverflow.com/questions/25187718/invalid-character-x00-after-top-level-value
  // [:length] to truncate extra bytes from connection.Read()
  err = json.Unmarshal(message[:length], &nonceMessage)

  s := generateSecret()
  for !hasNZeroes(computeNonceSecretHash(nonceMessage.Nonce, s), nonceMessage.N){
    s = generateSecret()
  }

  /*
  var s uint64
  for s = 0; uint64(s) < 18446744073709551615; s++ {
    fmt.Printf("%v\n", s)
    if hasNZeroes(computeNonceSecretHash(nonceMessage.Nonce, string(s)), nonceMessage.N){
      break
    }
  }
  */

  // Create SecretMessage
  var secretMsg SecretMessage
  secretMsg.Secret = s
  smsg, err := json.Marshal(secretMsg)
  if err != nil {
    fmt.Printf("Error encoding secret response: %v\n", err)
  }

  // Send message
  length, err = uconnection.Write(smsg)

  // Retrieve fserver info
  length, err = uconnection.Read(message)
  if err != nil {
    fmt.Printf("Error reading fServer response: %v\n", err)
  }
  var fim FortuneInfoMessage
  err = json.Unmarshal(message[:length], &fim)

  // Connect to fserver
  fserver, err := net.ResolveTCPAddr("tcp", fim.FortuneServer)
  if err != nil {
    fmt.Printf("Error resolving TCP address for fServer: %v\n", err)
  }
  tconnection, err := net.DialTCP("tcp", localTCPAddr, fserver)
  if err != nil {
    fmt.Printf("Error connecting to fServer: %v\n", err)
  }
  defer tconnection.Close()

  var fReqMessage FortuneReqMessage
  fReqMessage.FortuneNonce = fim.FortuneNonce

  fmsg, err := json.Marshal(fReqMessage)
  if err != nil {
    fmt.Printf("Error marshalling fortune message: %v", err)
  }
  tconnection.Write(fmsg)
  length, err = tconnection.Read(message)
  if err != nil {
    fmt.Printf("Error reading fortune message: %v", err)
  }

  var fortuneMsg FortuneMessage
  err = json.Unmarshal(message[:length], &fortuneMsg)
  if err != nil {
    fmt.Printf("Error unmarshalling fortune response: %v", err)
  }

  fmt.Printf("Fortune: %v\n", fortuneMsg.Fortune)
  // fmt.Printf("Rank: %v\n", fortuneMsg.Rank)
}

func generateSecret() string {
  bytes := make([]byte, 8)
  _, err := rand.Read(bytes)
  if err != nil {
    fmt.Printf("Error generating secret")
  }

  // return hex.EncodeToString(bytes)
  return string(binary.LittleEndian.Uint64(bytes))
}

// Returns a boolean indicating if given hash contains N zeroes
func hasNZeroes(hash string, n int64) bool {
  var zeroString string
  for i := int64(0); i < n; i++ {
    zeroString += "0"
  }

  return strings.HasSuffix(hash, zeroString)
}

// Returns the MD5 hash as a hex string for the (nonce + secret) value.
func computeNonceSecretHash(nonce string, secret string) string {
  h := md5.New()
  h.Write([]byte(nonce + secret))
  str := hex.EncodeToString(h.Sum(nil))
  return str
}
