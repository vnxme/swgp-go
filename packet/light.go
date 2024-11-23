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
	"encoding/binary"

	"github.com/database64128/swgp-go/slicehelper"
)

// lightHandler modifies the first 4 bytes of packets using XOR.
// The remainder of packets isn't changed.
//
// lightHandler implements [Handler].
type lightHandler struct {
	zero          uint32
	maxPacketSize int
}

// Encrypt implements [Handler.Encrypt].
func (h *lightHandler) Encrypt(dst, wgPacket []byte) ([]byte, error) {
	// Return packets smaller than a single message type field (4 bytes).
	if len(wgPacket) < WireGuardMessageTypeBytes {
		return append(dst, wgPacket...), nil
	}

	dst, b := slicehelper.Extend(dst, len(wgPacket))

	// Compose a new message type value by XORing an original message type value with the pre-defined zero
	newMessageType := binary.LittleEndian.Uint32(wgPacket[:WireGuardMessageTypeBytes]) ^ h.zero

	// Put the new message type value
	binary.LittleEndian.PutUint32(b[:WireGuardMessageTypeBytes], newMessageType)

	// Put everything else
	_ = copy(b[WireGuardMessageTypeBytes:], wgPacket[WireGuardMessageTypeBytes:])

	return dst, nil
}

// Decrypt implements [Handler.Decrypt].
func (h *lightHandler) Decrypt(dst, swgpPacket []byte) ([]byte, error) {
	return h.Encrypt(dst, swgpPacket)
}

// WithMaxPacketSize implements [Handler.WithMaxPacketSize].
func (h *lightHandler) WithMaxPacketSize(maxPacketSize int) Handler {
	if h.maxPacketSize == maxPacketSize {
		return h
	}
	return &lightHandler{
		zero:          h.zero,
		maxPacketSize: maxPacketSize,
	}
}

// NewLightHandler creates a "light" handler that
// uses the first 3 bytes of the given PSK to XOR
// message type values of all packets.
func NewLightHandler(psk []byte, maxPacketSize int) (Handler, error) {
	return &lightHandler{
		zero:          binary.BigEndian.Uint32(psk[:WireGuardMessageTypeBytes]) & WireGuardMessageTypeReservedZeroFilter,
		maxPacketSize: maxPacketSize,
	}, nil
}

const (
	WireGuardMessageTypeBytes              = 4
	WireGuardMessageTypeReservedZeroFilter = ^(uint32(0)) >> 8 << 8
)
