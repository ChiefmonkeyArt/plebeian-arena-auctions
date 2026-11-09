package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
)

type Event struct {
	ID        string     `json:"id"`
	Pubkey    string     `json:"pubkey"`
	CreatedAt int64      `json:"created_at"`
	Kind      int        `json:"kind"`
	Tags      [][]string `json:"tags"`
	Content   string     `json:"content"`
	Sig       string     `json:"sig"`
}

const (
	KindCreate = 1440
	KindBid    = 1441
	KindChat   = 1442
)

func nostrStr(sb *strings.Builder, s string) {
	sb.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			sb.WriteString(`\"`)
		case '\\':
			sb.WriteString(`\\`)
		case '\n':
			sb.WriteString(`\n`)
		case '\r':
			sb.WriteString(`\r`)
		case '\t':
			sb.WriteString(`\t`)
		case '\b':
			sb.WriteString(`\b`)
		case '\f':
			sb.WriteString(`\f`)
		default:
			if r < 0x20 {
				sb.WriteString(`\u00`)
				sb.WriteString(hex.EncodeToString([]byte{byte(r)}))
			} else {
				sb.WriteRune(r)
			}
		}
	}
	sb.WriteByte('"')
}

func (e *Event) Serialize() string {
	var sb strings.Builder
	sb.WriteString("[0,")
	nostrStr(&sb, e.Pubkey)
	sb.WriteByte(',')
	sb.WriteString(strconv.FormatInt(e.CreatedAt, 10))
	sb.WriteByte(',')
	sb.WriteString(strconv.Itoa(e.Kind))
	sb.WriteString(",[")
	for i, t := range e.Tags {
		if i > 0 {
			sb.WriteByte(',')
		}
		sb.WriteByte('[')
		for j, v := range t {
			if j > 0 {
				sb.WriteByte(',')
			}
			nostrStr(&sb, v)
		}
		sb.WriteByte(']')
	}
	sb.WriteString("],")
	nostrStr(&sb, e.Content)
	sb.WriteByte(']')
	return sb.String()
}

func (e *Event) Verify() error {
	if len(e.Pubkey) != 64 || len(e.ID) != 64 || len(e.Sig) != 128 {
		return errors.New("malformed event")
	}
	h := sha256.Sum256([]byte(e.Serialize()))
	if hex.EncodeToString(h[:]) != strings.ToLower(e.ID) {
		return errors.New("event id mismatch")
	}
	if !schnorrVerifyHash(h[:], e.Pubkey, e.Sig) {
		return errors.New("bad event signature")
	}
	return nil
}
