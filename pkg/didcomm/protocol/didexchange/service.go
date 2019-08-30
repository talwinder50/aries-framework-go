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
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
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
	connectionAck = connectionSpec + "ack"
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

// New return didexchange service
func New(store storage.Store, prov provider) *Service {
	return &Service{outboundTransport: prov.OutboundTransport(), store: store}
}

// Handle didexchange msg
func (s *Service) Handle(msg dispatcher.DIDCommMsg) error {
	thid, err := threadID(msg.Payload)
	if err != nil {
		return err
	}
	current, err := s.currentState(thid)
	if err != nil {
		return err
	}
	next, err := stateFromMsgType(msg.Type)
	if err != nil {
		return err
	}
	if !current.CanTransitionTo(next) {
		return errors.Errorf("invalid state transition: %s -> %s", current.Name(), next.Name())
	}
	// TODO call pre-transition listeners
	// TODO execute actions for the current state *and the next (if any)*. Eg. if we receive an
	//      invitation, execute actions for 'invited' state and then execute actions for
	//      'requested' state. Implement the relevant actions for each state in state.go.
	err = s.update(thid, next)
	if err != nil {
		return err
	}
	// TODO call post-transition listeners
	return nil
}

func threadID(payload []byte) (string, error) {
	msg := struct {
		ID     string           `json:"@id"`
		Thread decorator.Thread `json:"~thread,omitempty"`
	}{}
	err := json.Unmarshal(payload, &msg)
	if err != nil {
		return "", errors.Errorf("cannot unmarshal @id and ~thread: error=%s", err)
	}
	thid := msg.ID
	if len(msg.Thread.ID) > 0 {
		thid = msg.Thread.ID
	}
	return thid, nil
}

func (s *Service) currentState(thid string) (state, error) {
	name, err := s.store.Get(thid)
	if err != nil {
		// TODO this err check should be fixed in #195
		if strings.Contains(err.Error(), "not found") {
			return &null{}, nil
		}
		return nil, errors.Errorf("cannot fetch state from store: thid=%s err=%s", thid, err)
	}
	return stateFromName(string(name))
}

func (s *Service) update(thid string, state state) error {
	err := s.store.Put(thid, []byte(state.Name()))
	if err != nil {
		return errors.Errorf("failed to write to store: %s", err)
	}
	return nil
}

// Accept msg checks the msg type
func (s *Service) Accept(msgType string) bool {
	return msgType == connectionInvite ||
		msgType == connectionRequest ||
		msgType == connectionResponse ||
		msgType == connectionAck
}

// Name return service name
func (s *Service) Name() string {
	return DIDExchange
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
