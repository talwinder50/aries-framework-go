/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package exchange

import (
	"testing"

	mocktransport "github.com/hyperledger/aries-framework-go/pkg/internal/didcomm/transport/mock"
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
	oTr := mocktransport.NewOutboundTransport(successResponse)

	req := &Request{
		ID:    "5678876542345",
		Label: "Bob",
	}

	require.NoError(t, SendExchangeRequest(req, destinationURL, oTr))
	require.Error(t, SendExchangeRequest(nil, destinationURL, oTr))
}

func TestSendResponse(t *testing.T) {
	oTr := mocktransport.NewOutboundTransport(successResponse)

	resp := &Response{
		ID: "12345678900987654321",
		ConnectionSignature: &ConnectionSignature{
			Type: "did:trustbloc:RQkehfoFssiwQRuihskwoPSR;spec/ed25519Sha512_single/1.0/ed25519Sha512_single",
		},
	}

	require.NoError(t, SendExchangeResponse(resp, destinationURL, oTr))
	require.Error(t, SendExchangeResponse(nil, destinationURL, oTr))
}
