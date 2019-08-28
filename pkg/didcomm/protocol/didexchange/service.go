/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package didexchange

import (
	"encoding/base64"
	"encoding/json"
	"strings"

	"github.com/google/uuid"
	"github.com/hyperledger/aries-framework-go/pkg/common/metadata"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/dispatcher"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/transport"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
	errors "golang.org/x/xerrors"
)

const (
	// DIDExchange did exchange protocol
	DIDExchange        = "didexchange"
	connectionSpec     = metadata.AriesCommunityDID + ";spec/didexchange/1.0/"
	connectionInvite   = connectionSpec + "invitation"
	connectionRequest  = connectionSpec + "request"
	connectionResponse = connectionSpec + "response"
	//TODO : : Acknowledgement needs to follow RFCS-0015 for acks : https://github.com/hyperledger/aries-rfcs/tree/master/features/0015-acks
	connectionAck  = connectionSpec + "ack"
	nullState      = "null"
	invitedState   = "invited"
	requestedState = "requested"
	respondedState = "responded"
	completeState  = "completed"
)

// provider contains dependencies for the DID exchange protocol and is typically created by using aries.Context()
type provider interface {
	OutboundTransport() transport.OutboundTransport
}

// Service for DID exchange protocol
type Service struct {
	outboundTransport transport.OutboundTransport
	store             storage.Store
}

//state defines a didcomm service state
type state struct {
	MsgType string `json:"@type"`
	Current string
}

//key struct prepares the composite key for state persitance and lookup
type key struct {
	//protocol is defined in the msg type url for example "didexchange"
	protocol string
	//version is derived from msg type as well
	version string
	//thread id of the request
	thid string
}

// New return didexchange service
func New(store storage.Store, prov provider) *Service {
	return &Service{outboundTransport: prov.OutboundTransport(), store: store}
}

// Handle didexchange msg
func (s *Service) Handle(msg dispatcher.DIDCommMsg) error {
	//populate request type, protocol, version required for composite key
	msgType := strings.Split(msg.Type, "/")
	pk := &key{
		protocol: msgType[1],
		version:  msgType[2],
	}
	switch msg.Type {
	case connectionInvite:
		invitation := &Invitation{}
		err := json.Unmarshal(msg.Payload, invitation)
		if err != nil {
			return err
		}
		pk.thid = invitation.ID
		state := &state{MsgType: invitation.Type, Current: ""}
		return s.invitation(state, pk)
	case connectionRequest:
		request := &Request{}
		err := json.Unmarshal(msg.Payload, request)
		if err != nil {
			return err
		}
		pk.thid = request.Thread.ID
		state := &state{MsgType: request.Type, Current: ""}
		return s.request(state, pk)
	case connectionResponse:
		response := &Response{}
		err := json.Unmarshal(msg.Payload, response)
		if err != nil {
			return err
		}
		pk.thid = response.Thread.ID
		state := &state{MsgType: response.Type, Current: ""}
		return s.response(state, pk)
	case connectionAck:
		ack := &Ack{}
		err := json.Unmarshal(msg.Payload, ack)
		if err != nil {
			return err
		}
		pk.thid = ack.Thread.ID
		state := &state{MsgType: ack.Type, Current: ""}
		return s.ack(state, pk)

	default:
		return errors.New("Message type  not supported")
	}

}

func (s *Service) checkAndValidateState(state *state, pk *key) (string, error) {

	if pk.thid == "" && (state.MsgType == connectionRequest || state.MsgType == connectionResponse || state.MsgType == connectionAck) {
		return "", errors.Errorf("Thread id in the %w is empty, therefor state cannot be validated", state.MsgType)
	}

	var respBytes []byte
	var err error
	//fetch from store using the composite key
	if state.MsgType == connectionInvite {
		respBytes, err = s.store.Get(pk.String())
		if respBytes == nil && strings.Contains(err.Error(), "not found") {
			return nullState, nil
		}
	} else {
		respBytes, err = s.store.Get(pk.String())
		if err != nil {
			return "", err
		}
	}
	currentState, err := unmarshallResp(respBytes)
	if err != nil {
		return "", err
	}

	return currentState, nil
}
func (s *Service) persistState(state *state, pk *key) error {
	stateBytes, err := marshallState(state)
	if err != nil {
		return err
	}
	//persist in the store
	err = s.store.Put(pk.String(), stateBytes)
	if err != nil {
		return err
	}
	return nil
}

func (s *Service) invitation(state *state, pk *key) error {
	//check Current state
	currentState, err := s.checkAndValidateState(state, pk)
	if err != nil {
		return err
	}
	if currentState == nullState {
		state.Current = invitedState
		err := s.persistState(state, pk)
		if err != nil {
			return err

		}
	} else {
		return errors.New("Required Current state : Null for invite connection")
	}
	return nil
}

func (s *Service) request(state *state, pk *key) error {
	//check Current state
	currentState, err := s.checkAndValidateState(state, pk)
	if err != nil {
		return err
	}
	if currentState == invitedState {
		state.Current = requestedState
		err := s.persistState(state, pk)
		if err != nil {
			return err
		}
	} else {
		return errors.New("Required Current state : Invited  for request connection")
	}
	return nil
}

func (s *Service) response(state *state, pk *key) error {
	//check Current state
	currentState, err := s.checkAndValidateState(state, pk)
	if err != nil {
		return err
	}
	if currentState == requestedState {
		state.Current = respondedState

		err := s.persistState(state, pk)
		if err != nil {
			return err
		}
	} else {
		return errors.New("Required Current state : Requested for response connection")
	}
	return nil
}

func (s *Service) ack(state *state, pk *key) error {
	//check Current state
	currentState, err := s.checkAndValidateState(state, pk)
	if err != nil {
		return err
	}
	if currentState == respondedState {
		state.Current = completeState
		err := s.persistState(state, pk)
		if err != nil {
			return err
		}
	} else {
		return errors.New("Required Current state : Responded for ack connection")
	}
	return nil
}

// Accept msg checks the msg type
func (s *Service) Accept(msgType string) bool {

	if msgType == connectionInvite || msgType == connectionRequest || msgType == connectionResponse {
		return true
	}
	return false
}

// Name return service name
func (s *Service) Name() string {
	return DIDExchange
}

//String prepares the composite key
func (pk *key) String() string {
	key := []string{pk.thid, pk.protocol, pk.version}
	return strings.Join(key, "")
}
func unmarshallResp(respBytes []byte) (string, error) {
	state := &state{}
	err := json.Unmarshal(respBytes, state)
	if err != nil {
		return "", err
	}
	currentState := state.Current

	return currentState, nil
}

func marshallState(state *state) ([]byte, error) {
	return json.Marshal(state)
}

// Connection return connection
func (s *Service) Connection(id string) {
	// TODO add Connection logic

}

// Connections return all connections
func (s *Service) Connections() {
	// TODO add Connections logic

}

// SendExchangeRequest sends exchange request
func (s *Service) SendExchangeRequest(exchangeRequest *Request, destination string) error {
	if exchangeRequest == nil {
		return errors.New("exchangeRequest cannot be nil")
	}

	exchangeRequest.Type = connectionRequest

	// ignore response data as it is not used in this communication mode as defined in the spec
	_, err := s.marshalAndSend(exchangeRequest, "Error Marshalling Exchange Request", destination)
	return err
}

// SendExchangeResponse sends exchange response
func (s *Service) SendExchangeResponse(exchangeResponse *Response, destination string) error {
	if exchangeResponse == nil {
		return errors.New("exchangeResponse cannot be nil")
	}

	exchangeResponse.Type = connectionResponse

	// ignore response data as it is not used in this communication mode as defined in the spec
	_, err := s.marshalAndSend(exchangeResponse, "Error Marshalling Exchange Response", destination)
	return err
}

//CreateInvitation creates invitation
func (s *Service) CreateInvitation() (*InvitationRequest, error) {
	return &InvitationRequest{Invitation: &Invitation{
		Type:            connectionInvite,
		ID:              uuid.New().String(),
		Label:           "agent",                        //TODO get the value from config #175
		RecipientKeys:   nil,                            //TODO #178
		ServiceEndpoint: "https://example.com/endpoint", //TODO get the value from config #175
	},
	}, nil
}

func (s *Service) marshalAndSend(data interface{}, errorMsg, destination string) (string, error) {
	jsonString, err := json.Marshal(data)
	if err != nil {
		return "", errors.Errorf("%s : %w", errorMsg, err)
	}
	return s.outboundTransport.Send(string(jsonString), destination)
}

func encodedExchangeInvitation(inviteMessage *Invitation) (string, error) {
	inviteMessage.Type = connectionInvite

	invitationJSON, err := json.Marshal(inviteMessage)
	if err != nil {
		return "", errors.Errorf("JSON Marshal Error : %w", err)
	}

	return base64.URLEncoding.EncodeToString(invitationJSON), nil
}

// GenerateInviteWithPublicDID generates the DID exchange invitation string with public DID
func GenerateInviteWithPublicDID(invite *Invitation) (string, error) {
	if invite.ID == "" || invite.DID == "" {
		return "", errors.New("ID and DID are mandatory")
	}

	return encodedExchangeInvitation(invite)
}

// GenerateInviteWithKeyAndEndpoint generates the DID exchange invitation string with recipient key and endpoint
func GenerateInviteWithKeyAndEndpoint(invite *Invitation) (string, error) {
	if invite.ID == "" || invite.ServiceEndpoint == "" || len(invite.RecipientKeys) == 0 {
		return "", errors.New("ID, Service Endpoint and Recipient Key are mandatory")
	}

	return encodedExchangeInvitation(invite)
}
