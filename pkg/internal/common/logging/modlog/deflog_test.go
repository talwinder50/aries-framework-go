/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package modlog

import (
	"testing"

	"github.com/hyperledger/aries-framework-go/pkg/internal/common/logging/metadata"
)

func TestDefLog(t *testing.T) {
	const module = "sample-module"

	// prepare default logging
	defLog := NewDefLog(module)

	logger := NewModLog(defLog, module)
	SwitchLogOutputToBuffer(logger)
	VerifyDefaultLogging(t, logger, module, metadata.SetLevel)
}

func TestDefLogWithoutCallerInfo(t *testing.T) {
	const module = "sample-module-no-info"

	// prepare default logging
	defLog := NewDefLog(module)

	logger := NewModLog(defLog, module)
	SwitchLogOutputToBuffer(logger)

	// disable caller info and test
	metadata.HideCallerInfo(module, metadata.INFO)
	logger.Infof(msgFormat, msgArg1, msgArg2)
	matchDefLogOutput(t, module, metadata.INFO, metadata.INFO, false)

}
