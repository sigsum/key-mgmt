package agent

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"sync"
)

const (
	SSH_AGENT_FAILURE             = 5
	SSH_AGENTC_REQUEST_IDENTITIES = 11
	SSH_AGENT_IDENTITIES_ANSWER   = 12
	SSH_AGENTC_SIGN_REQUEST       = 13
	SSH_AGENT_SIGN_RESPONSE       = 14
	// Arbitrary maximum size of received agent messages.
	maxSize = 10000
)

// Returns signature formatted as an SSH signature (without outer
// length field).
type SSHSign func([]byte) ([]byte, error)

type signRequest struct {
	pubKey []byte
	data   []byte
}

type signRequestWithSeqNo struct {
	requestData    []byte
	sequenceNumber int
}

type response struct {
	data           []byte
	sequenceNumber int
}

func readSignRequest(r io.Reader) (req signRequest, err error) {
	req.pubKey, err = readString(r, maxSize)
	if err != nil {
		return
	}
	req.data, err = readString(r, maxSize)
	if err != nil {
		return
	}
	// Flags, currently ignored.
	_, err = readUint32(r)
	return
}

// The map keys are SSH public key blobs (without outer length field).
func ServeAgent(r io.Reader, w io.Writer, keys map[string]SSHSign, nWorkers int) error {
	// The exitCh channel is used in case of error in ReadRequests()
	exitCh := make(chan error, 1)
	requestCh := make(chan signRequestWithSeqNo, 100)
	responseCh := make(chan response, 100)
	go ReadRequests(r, keys, exitCh, requestCh, responseCh)
	go WriteResponses(w, responseCh)
	var wg sync.WaitGroup
	for i := 0; i < nWorkers; i++ {
		wg.Add(1)
		go HandleRequests(requestCh, responseCh, keys, &wg)
	}
	err := <-exitCh
	log.Printf("ServeAgent error: %v", err)
	// We close requestCh which should cause all HandleRequests goroutines to finish
	close(requestCh)
	// Wait for all HandleRequests goroutines to finish
	wg.Wait()
	// Now we can close the responseCh channel, we know nothing more will be written to it
	close(responseCh)
	return err
}

func HandleRequests(requestCh chan signRequestWithSeqNo, responseCh chan response, keys map[string]SSHSign, wg *sync.WaitGroup) {
	for {
		newRequest, more := <-requestCh
		if more {
			err := HandleRequest(keys, newRequest.requestData, newRequest.sequenceNumber, responseCh)
			if err != nil {
				log.Printf("HandleRequest failed: %v", err)
			}
		} else {
			wg.Done()
			return
		}
	}
}

// Handles a single request
func HandleRequest(keys map[string]SSHSign, data []byte, sequenceNumber int, responseCh chan response) error {
	t, msg := data[0], data[1:]
	// The write methods on bytes.Buffer are documented to
	// always return a nil error. Therefore all related
	// error return values below are ignored.
	var rsp bytes.Buffer
	switch t {
	case SSH_AGENTC_REQUEST_IDENTITIES:
		if len(msg) > 0 {
			return fmt.Errorf("invalid message, %d left-over bytes in list request", len(msg))
		}
		rsp.WriteByte(SSH_AGENT_IDENTITIES_ANSWER)
		writeUint32(&rsp, uint32(len(keys)))
		for k, _ := range keys {
			writeString(&rsp, k)
			// Arbitrary comment
			writeString(&rsp, "oracle key")
		}
	case SSH_AGENTC_SIGN_REQUEST:
		req, err := parseBytes(msg, nil, readSignRequest)
		if err != nil {
			return err
		}
		signer, ok := keys[string(req.pubKey)]
		if !ok {
			rsp.WriteByte(SSH_AGENT_FAILURE)
			break
		}
		sig, err := signer(req.data)
		if err != nil {
			log.Printf("signing failed: %v", err)
			rsp.WriteByte(SSH_AGENT_FAILURE)
			break
		}
		rsp.WriteByte(SSH_AGENT_SIGN_RESPONSE)
		writeString(&rsp, sig)
	default:
		rsp.WriteByte(SSH_AGENT_FAILURE)
	}
	responseCh <- response{rsp.Bytes(), sequenceNumber}
	return nil
}

// Reads incoming requests and calls HandleRequest() for each request
func ReadRequests(r io.Reader, keys map[string]SSHSign, exitCh chan error, requestCh chan signRequestWithSeqNo, responseCh chan response) {
	sequenceNumber := 0
	for {
		data, err := readString(r, maxSize)
		if err != nil {
			exitCh <- err
			return
		}
		if len(data) == 0 {
			err := fmt.Errorf("invalid empty agent message")
			exitCh <- err
			return
		}
		sequenceNumber = sequenceNumber + 1
		requestCh <- signRequestWithSeqNo{data, sequenceNumber}
	}
}

// Writes responses in the correct order, based on sequence numbers
func WriteResponses(w io.Writer, responseCh chan response) {
	nextSequenceNumberToWrite := 1
	pendingResponses := map[int]response{}
	for {
		newResponse, more := <-responseCh
		if !more {
			return
		}
		pendingResponses[newResponse.sequenceNumber] = newResponse
		// Write as many responses as we can
		for {
			rsp, ok := pendingResponses[nextSequenceNumberToWrite]
			if ok == false {
				// We don't have the right sequence number, so we don't write anything more.
				break
			}
			if err := writeString(w, rsp.data); err != nil {
				log.Printf("Error in WriteResponses: writeString failed: %v", err)
			}
			delete(pendingResponses, nextSequenceNumberToWrite)
			nextSequenceNumberToWrite = nextSequenceNumberToWrite + 1
		}
	}
}
