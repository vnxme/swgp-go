// Copyright 2024 VNXME
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package packet

import (
	"crypto/rand"
	"strconv"
	"testing"
)

func newLightHandler(t *testing.T) Handler {
	t.Helper()

	psk := make([]byte, 32)
	if _, err := rand.Read(psk); err != nil {
		t.Fatal(err)
	}

	h, err := NewLightHandler(psk, 1452)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func TestLightHandler(t *testing.T) {
	h := newLightHandler(t)

	for _, msg := range []struct {
		name    string
		msgType byte
	}{
		{"HandshakeInitiation", WireGuardMessageTypeHandshakeInitiation},
		{"HandshakeResponse", WireGuardMessageTypeHandshakeResponse},
		{"HandshakeCookieReply", WireGuardMessageTypeHandshakeCookieReply},
		{"Data", WireGuardMessageTypeData},
	} {
		t.Run(msg.name, func(t *testing.T) {
			for _, length := range []int{0, 1, 16, 128, 1280} {
				t.Run(strconv.Itoa(length), func(t *testing.T) {
					testHandler(t, msg.msgType, length, h, nil, nil, nil)
				})
			}
		})
	}
}
