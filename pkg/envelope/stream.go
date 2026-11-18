package envelope

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	StreamMagic            = "SHUNAS1"
	StreamMagicLen         = 7
	StreamHeaderSize       = 32 // 7 (Magic) + 1 (AlgID) + 4 (KeyVersion) + 4 (ChunkSize) + 16 (StreamID)
	StreamIDSize           = 16
	DefaultStreamChunkSize = 65536
	MinStreamChunkSize     = 4096
	MaxStreamChunkSize     = 4194304
	StreamDefaultKeyVer    = 1

	chunkFrameHeaderSize = 5 // 1 (FinalFlag) + 4 (PlainLen)
)

// SealStream encrypts r to w using the SHUNAS1 chunked XChaCha20-Poly1305 stream format.
func SealStream(r io.Reader, w io.Writer, key []byte, aad []byte) error {
	return SealStreamWithOptions(r, w, key, StreamDefaultKeyVer, DefaultStreamChunkSize, aad)
}

// SealStreamWithOptions encrypts r to w with an explicit keyVersion and chunkSize.
func SealStreamWithOptions(r io.Reader, w io.Writer, key []byte, keyVersion uint32, chunkSize uint32, aad []byte) error {
	if len(key) != KeySize {
		return ErrInvalidKey
	}
	if chunkSize == 0 {
		chunkSize = DefaultStreamChunkSize
	}
	if chunkSize < MinStreamChunkSize || chunkSize > MaxStreamChunkSize {
		return fmt.Errorf("chunk size %d out of bounds [%d, %d]", chunkSize, MinStreamChunkSize, MaxStreamChunkSize)
	}

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return fmt.Errorf("init xchacha20poly1305: %w", err)
	}

	var header [StreamHeaderSize]byte
	copy(header[:StreamMagicLen], StreamMagic)
	header[7] = AlgXChaCha20Poly1305
	binary.BigEndian.PutUint32(header[8:12], keyVersion)
	binary.BigEndian.PutUint32(header[12:16], chunkSize)
	if _, err := io.ReadFull(rand.Reader, header[16:32]); err != nil {
		return fmt.Errorf("generate stream id: %w", err)
	}
	streamID := header[16:32]

	if _, err := w.Write(header[:]); err != nil {
		return fmt.Errorf("write stream header: %w", err)
	}

	buf := make([]byte, int(chunkSize)+1)
	var peeked byte
	hasPeeked := false
	var counter uint64

	var nonce [NonceSlotSize]byte
	copy(nonce[:StreamIDSize], streamID)
	chunkAADBuf := make([]byte, len(aad)+StreamMagicLen+4+StreamIDSize+8+1)

	for {
		offset := 0
		if hasPeeked {
			buf[0] = peeked
			offset = 1
			hasPeeked = false
		}

		n, readErr := io.ReadFull(r, buf[offset:int(chunkSize)])
		total := offset + n

		var finalFlag byte
		if readErr == io.EOF || readErr == io.ErrUnexpectedEOF {
			finalFlag = 0x01
		} else if readErr != nil {
			return fmt.Errorf("read stream input: %w", readErr)
		} else {
			// Exact chunkSize read; peek 1 byte to know whether EOF immediately follows.
			var one [1]byte
			pn, perr := io.ReadFull(r, one[:])
			if perr == io.EOF || perr == io.ErrUnexpectedEOF || pn == 0 {
				finalFlag = 0x01
			} else if perr != nil {
				return fmt.Errorf("peek stream input: %w", perr)
			} else {
				finalFlag = 0x00
				peeked = one[0]
				hasPeeked = true
			}
		}

		if total == 0 && !(finalFlag == 0x01 && counter == 0) {
			return errors.New("unexpected empty intermediate chunk")
		}

		binary.BigEndian.PutUint64(nonce[StreamIDSize:NonceSlotSize], counter)
		chunkAAD := buildChunkAAD(chunkAADBuf[:0], aad, keyVersion, streamID, counter, finalFlag)

		var frameHdr [chunkFrameHeaderSize]byte
		frameHdr[0] = finalFlag
		binary.BigEndian.PutUint32(frameHdr[1:5], uint32(total))

		ct := aead.Seal(nil, nonce[:], buf[:total], chunkAAD)
		if _, err := w.Write(frameHdr[:]); err != nil {
			return fmt.Errorf("write chunk frame header: %w", err)
		}
		if _, err := w.Write(ct); err != nil {
			return fmt.Errorf("write chunk ciphertext: %w", err)
		}

		if finalFlag == 0x01 {
			return nil
		}
		if counter == math.MaxUint64 {
			return errors.New("stream chunk counter overflow")
		}
		counter++
	}
}

// UnsealStream verifies and decrypts a SHUNAS1 stream from r into w.
func UnsealStream(r io.Reader, w io.Writer, key []byte, aad []byte) error {
	if len(key) != KeySize {
		return ErrInvalidKey
	}
	return UnsealStreamWithKeyLookup(r, w, func(uint32) ([]byte, error) {
		return key, nil
	}, aad)
}

// UnsealStreamWithKeyLookup decrypts a SHUNAS1 stream using a key lookup callback keyed by header KeyVersion.
func UnsealStreamWithKeyLookup(r io.Reader, w io.Writer, lookup func(keyVersion uint32) ([]byte, error), aad []byte) error {
	var header [StreamHeaderSize]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return corruptErr("missing or truncated SHUNAS1 stream header", err)
	}
	if string(header[:StreamMagicLen]) != StreamMagic {
		return corruptErr("invalid SHUNAS1 stream magic", nil)
	}
	if header[7] != AlgXChaCha20Poly1305 {
		return corruptErr(fmt.Sprintf("unsupported SHUNAS1 algorithm 0x%02x", header[7]), nil)
	}

	keyVersion := binary.BigEndian.Uint32(header[8:12])
	chunkSize := binary.BigEndian.Uint32(header[12:16])
	if chunkSize < MinStreamChunkSize || chunkSize > MaxStreamChunkSize {
		return corruptErr(fmt.Sprintf("invalid SHUNAS1 chunk size %d", chunkSize), nil)
	}
	streamID := header[16:32]

	key, err := lookup(keyVersion)
	if err != nil {
		return err
	}
	if len(key) != KeySize {
		return ErrInvalidKey
	}

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return fmt.Errorf("init xchacha20poly1305: %w", err)
	}

	var expectedCounter uint64
	var nonce [NonceSlotSize]byte
	copy(nonce[:StreamIDSize], streamID)
	chunkAADBuf := make([]byte, len(aad)+StreamMagicLen+4+StreamIDSize+8+1)
	ctBuf := make([]byte, int(chunkSize)+TagSize)

	for {
		var frameHdr [chunkFrameHeaderSize]byte
		if _, err := io.ReadFull(r, frameHdr[:]); err != nil {
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				return corruptErr("premature EOF before final SHUNAS1 chunk", err)
			}
			return fmt.Errorf("read chunk header: %w", err)
		}

		finalFlag := frameHdr[0]
		if finalFlag != 0x00 && finalFlag != 0x01 {
			return corruptErr(fmt.Sprintf("invalid SHUNAS1 final flag 0x%02x", finalFlag), nil)
		}

		plainLen := binary.BigEndian.Uint32(frameHdr[1:5])
		if plainLen > chunkSize {
			return corruptErr(fmt.Sprintf("SHUNAS1 chunk plain length %d exceeds chunk size %d", plainLen, chunkSize), nil)
		}
		if plainLen == 0 && !(finalFlag == 0x01 && expectedCounter == 0) {
			return corruptErr("zero-length chunk only permitted on empty final stream", nil)
		}

		ctLen := int(plainLen) + TagSize
		if _, err := io.ReadFull(r, ctBuf[:ctLen]); err != nil {
			return corruptErr("truncated SHUNAS1 chunk payload", err)
		}

		binary.BigEndian.PutUint64(nonce[StreamIDSize:NonceSlotSize], expectedCounter)
		chunkAAD := buildChunkAAD(chunkAADBuf[:0], aad, keyVersion, streamID, expectedCounter, finalFlag)

		pt, err := aead.Open(nil, nonce[:], ctBuf[:ctLen], chunkAAD)
		if err != nil {
			return corruptErr(fmt.Sprintf("SHUNAS1 chunk %d authentication failed", expectedCounter), err)
		}

		if len(pt) > 0 {
			if _, err := w.Write(pt); err != nil {
				return fmt.Errorf("write plaintext chunk: %w", err)
			}
		}

		if finalFlag == 0x01 {
			var extra [1]byte
			if _, err := io.ReadFull(r, extra[:]); err != io.EOF {
				return corruptErr("unexpected trailing bytes after final SHUNAS1 chunk", err)
			}
			return nil
		}

		if expectedCounter == math.MaxUint64 {
			return corruptErr("SHUNAS1 chunk counter overflow", nil)
		}
		expectedCounter++
	}
}

func buildChunkAAD(dst, callerAAD []byte, keyVersion uint32, streamID []byte, counter uint64, finalFlag byte) []byte {
	dst = append(dst, callerAAD...)
	dst = append(dst, StreamMagic...)
	var b4 [4]byte
	binary.BigEndian.PutUint32(b4[:], keyVersion)
	dst = append(dst, b4[:]...)
	dst = append(dst, streamID...)
	var b8 [8]byte
	binary.BigEndian.PutUint64(b8[:], counter)
	dst = append(dst, b8[:]...)
	dst = append(dst, finalFlag)
	return dst
}
