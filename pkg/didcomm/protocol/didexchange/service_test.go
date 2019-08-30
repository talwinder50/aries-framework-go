/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package didexchange

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"testing"

	mocktransport "github.com/hyperledger/aries-framework-go/pkg/internal/didcomm/transport/mock"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/dispatcher"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/transport"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
	"github.com/hyperledger/aries-framework-go/pkg/storage/leveldb"
	"github.com/stretchr/testify/require"
)

const (
	destinationURL  = "https://localhost:8090"
	successResponse = "success"
)

func TestGenerateInviteWithPublicDID(t *testing.T) {
	invite, err := GenerateInviteWithPublicDID(&Invitation{
		ID:    "12345678900987654321",
		Label: "Alice",
		DID:   "did:example:ZadolSRQkehfo",
	})

	require.NoError(t, err)
	require.NotEmpty(t, invite)

	invite, err = GenerateInviteWithPublicDID(&Invitation{
		ID:    "12345678900987654321",
		Label: "Alice",
	})
	require.Error(t, err)
	require.Empty(t, invite)

	invite, err = GenerateInviteWithPublicDID(&Invitation{
		Label: "Alice",
		DID:   "did:example:ZadolSRQkehfo",
	})
	require.Error(t, err)
	require.Empty(t, invite)
}

func TestGenerateInviteWithKeyAndEndpoint(t *testing.T) {
	invite, err := GenerateInviteWithKeyAndEndpoint(&Invitation{
		ID:              "12345678900987654321",
		Label:           "Alice",
		RecipientKeys:   []string{"8HH5gYEeNc3z7PYXmd54d4x6qAfCNrqQqEB3nS7Zfu7K"},
		ServiceEndpoint: "https://example.com/endpoint",
		RoutingKeys:     []string{"8HH5gYEeNc3z7PYXmd54d4x6qAfCNrqQqEB3nS7Zfu7K"},
	})
	require.NoError(t, err)
	require.NotEmpty(t, invite)

	invite, err = GenerateInviteWithKeyAndEndpoint(&Invitation{
		Label:           "Alice",
		RecipientKeys:   []string{"8HH5gYEeNc3z7PYXmd54d4x6qAfCNrqQqEB3nS7Zfu7K"},
		ServiceEndpoint: "https://example.com/endpoint",
		RoutingKeys:     []string{"8HH5gYEeNc3z7PYXmd54d4x6qAfCNrqQqEB3nS7Zfu7K"},
	})
	require.Error(t, err)
	require.Empty(t, invite)

	invite, err = GenerateInviteWithKeyAndEndpoint(&Invitation{
		ID:            "12345678900987654321",
		Label:         "Alice",
		RecipientKeys: []string{"8HH5gYEeNc3z7PYXmd54d4x6qAfCNrqQqEB3nS7Zfu7K"},
		RoutingKeys:   []string{"8HH5gYEeNc3z7PYXmd54d4x6qAfCNrqQqEB3nS7Zfu7K"},
	})
	require.Error(t, err)
	require.Empty(t, invite)

	invite, err = GenerateInviteWithKeyAndEndpoint(&Invitation{
		ID:              "12345678900987654321",
		Label:           "Alice",
		ServiceEndpoint: "https://example.com/endpoint",
		RoutingKeys:     []string{"8HH5gYEeNc3z7PYXmd54d4x6qAfCNrqQqEB3nS7Zfu7K"},
	})
	require.Error(t, err)
	require.Empty(t, invite)
}

func TestSendRequest(t *testing.T) {
	prov := New(nil, &mockProvider{})

	req := &Request{
		ID:    "5678876542345",
		Label: "Bob",
	}

	require.NoError(t, prov.SendExchangeRequest(req, destinationURL))
	require.Error(t, prov.SendExchangeRequest(nil, destinationURL))
}

func TestSendResponse(t *testing.T) {
	prov := New(nil, &mockProvider{})

	resp := &Response{
		ID: "12345678900987654321",
		ConnectionSignature: &ConnectionSignature{
			Type: "did:trustbloc:RQkehfoFssiwQRuihskwoPSR;spec/ed25519Sha512_single/1.0/ed25519Sha512_single",
		},
	}

	require.NoError(t, prov.SendExchangeResponse(resp, destinationURL))
	require.Error(t, prov.SendExchangeResponse(nil, destinationURL))
}

func TestCreateInvitation(t *testing.T) {
	prov := New(nil, &mockProvider{})
	inviteReq, err := prov.CreateInvitation()
	require.NoError(t, err)
	require.NotNil(t, inviteReq)
	require.Equal(t, inviteReq.Invitation.Type, connectionInvite)
	require.NotEmpty(t, inviteReq.Invitation.Label)
	require.NotEmpty(t, inviteReq.Invitation.ID)
	require.NotEmpty(t, inviteReq.Invitation.ServiceEndpoint)
}

func TestService_Handle(t *testing.T) {
	dbstore := setup(t)
	m := mockProvider{}
	s := &Service{outboundTransport: m.OutboundTransport(), store: dbstore}

	//Invitation is sent by Alice
	payloadBytes, err := json.Marshal(
		&Invitation{
			Type:  "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/didexchange/1.0/invitation",
			ID:    "12345678900987654324",
			Label: "Alice",
			DID:   "did:sov:QmWbsNYhMrjHiqZDTUTEJs",
		})
	require.NoError(t, err)

	msg := dispatcher.DIDCommMsg{Type: "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/didexchange/1.0/invitation", Payload: payloadBytes}
	err = s.Handle(msg)
	require.NoError(t, err)

	//Invitation accepted and Bob is sending exchange request to Alice
	payloadBytes, err = json.Marshal(
		&Request{
			Type:   "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/didexchange/1.0/request",
			ID:     "5369752154652",
			Label:  "Bob",
			Thread: &decorator.Thread{ID: "12345678900987654324"},
			Connection: &Connection{
				DID: "B.did@B:A",
			},
		})
	require.NoError(t, err)

	msg = dispatcher.DIDCommMsg{Type: "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/didexchange/1.0/request", Payload: payloadBytes}
	err = s.Handle(msg)
	require.NoError(t, err)

	//Alice is sending exchange-response to BOB
	payloadBytes, err = json.Marshal(
		&Response{
			Type:   "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/didexchange/1.0/request",
			ID:     "13354576764562",
			Thread: &decorator.Thread{ID: "12345678900987654324"},
			ConnectionSignature: &ConnectionSignature{
				Type: "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/signature/1.0/ed25519Sha512_single",
			},
		})
	require.NoError(t, err)

	msg = dispatcher.DIDCommMsg{Type: "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/didexchange/1.0/response", Payload: payloadBytes}
	err = s.Handle(msg)
	require.NoError(t, err)

	//BOB is sending ack. TODO: This has to be done using RFCs 0015

	//Alice is sending exchange-response to BOB
	payloadBytes, err = json.Marshal(
		&Ack{
			Type:   "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/didexchange/1.0/request",
			ID:     "123564324344",
			Status: "OK",
			Thread: &decorator.Thread{ID: "12345678900987654324"},
		})
	require.NoError(t, err)
	msg = dispatcher.DIDCommMsg{Type: "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/didexchange/1.0/ack", Payload: payloadBytes}
	err = s.Handle(msg)
	require.NoError(t, err)

	msg = dispatcher.DIDCommMsg{Type: "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/didexchange/1.0/yzaldh", Payload: payloadBytes}
	err = s.Handle(msg)
	require.Error(t, err)
	require.Equal(t, err.Error(), "Message type  not supported")
}
func TestService_Accept(t *testing.T) {
	dbstore := setup(t)
	m := mockProvider{}
	s := &Service{outboundTransport: m.OutboundTransport(), store: dbstore}

	resp := s.Accept("did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/didexchange/1.0/invitation")
	require.Equal(t, true, resp)

	resp = s.Accept("did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/didexchange/1.0/request")
	require.Equal(t, true, resp)

	resp = s.Accept("did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/didexchange/1.0/response")
	require.Equal(t, true, resp)

	resp = s.Accept("unsupported msg type")
	require.Equal(t, false, resp)

}

func TestCheckAndPersistState(t *testing.T) {
	dbstore := setup(t)
	m := mockProvider{}
	s := &Service{outboundTransport: m.OutboundTransport(), store: dbstore}

	state1 := &state{MsgType: "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/didexchange/1.0/invitation", Current: nullState}
	pk1 := &key{protocol: "didexchange", version: "1.0", thid: "12345678900987654321"}

	err := s.persistState(state1, pk1)
	require.NoError(t, err)

	state2 := &state{MsgType: "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/didexchange/1.0/invitation", Current: ""}
	pk2 := &key{protocol: "didexchange", version: "1.0", thid: "12345678900987654321"}
	currentState, err := s.checkAndValidateState(state2, pk2)
	require.Equal(t, nullState, currentState)
	require.NoError(t, err)

	state3 := &state{MsgType: "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/didexchange/1.0/request", Current: invitedState}
	pk3 := &key{protocol: "didexchange", version: "1.0", thid: "12345678900987654321"}

	err = s.persistState(state3, pk3)
	require.NoError(t, err)

	currentState, err = s.checkAndValidateState(state3, pk3)
	require.NoError(t, err)
	require.Equal(t, invitedState, currentState)

	//empty thread id in the request
	pk4 := &key{protocol: "didexchange", version: "1.0", thid: ""}
	currentState, err = s.checkAndValidateState(state3, pk4)
	require.Error(t, err)
	require.Contains(t, err.Error(), "state cannot be validated")
	require.Equal(t, currentState, "")

	//key not found in the db and message type is request
	pk4 = &key{protocol: "didexchange", version: "1.0", thid: "12345678900987654340"}
	currentState, err = s.checkAndValidateState(state3, pk4)
	require.Error(t, err)
	require.Equal(t, err.Error(), "leveldb: not found")
	require.Equal(t, "", currentState)

	state4 := &state{}
	pk5 := &key{}

	// persist - empty key
	err = s.persistState(state4, pk5)
	require.Error(t, err)
	require.Equal(t, err.Error(), "Key and value are mandatory")

}

func TestRequestResponseAndAck(t *testing.T) {
	dbstore := setup(t)
	m := mockProvider{}
	s := &Service{outboundTransport: m.OutboundTransport(), store: dbstore}
	state := &state{MsgType: "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/didexchange/1.0/response", Current: nullState}
	pk := &key{protocol: "didexchange", version: "1.0", thid: "12345678900987654321"}

	err := s.persistState(state, pk)
	require.NoError(t, err)

	err = s.request(state, pk)
	require.Error(t, err)
	require.Equal(t, err.Error(), "Required Current state : Invited  for request connection")

	err = s.response(state, pk)
	require.Error(t, err)
	require.Equal(t, err.Error(), "Required Current state : Requested for response connection")

	err = s.ack(state, pk)
	require.Error(t, err)
	require.Equal(t, err.Error(), "Required Current state : Responded for ack connection")

}

type mockProvider struct {
}

func (p *mockProvider) OutboundTransport() transport.OutboundTransport {
	return mocktransport.NewOutboundTransport(successResponse)
}

func setup(t testing.TB) storage.Store {
	path, cleanup := setupLevelDB(t)
	defer cleanup()

	prov, err := leveldb.NewProvider(path)
	require.NoError(t, err)
	dbstore, err := prov.GetStoreHandle()
	require.NoError(t, err)
	return dbstore
}
func setupLevelDB(t testing.TB) (string, func()) {
	dbPath, err := ioutil.TempDir("", "db")
	if err != nil {
		t.Fatalf("Failed to create leveldb directory: %s", err)
	}
	return dbPath, func() {
		err := os.RemoveAll(dbPath)
		if err != nil {
			t.Fatalf("Failed to clear leveldb directory: %s", err)
		}
	}
}
