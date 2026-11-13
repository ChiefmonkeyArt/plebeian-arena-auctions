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

// The auction kind map: the 1440 series, one place only (merged protocol spec
// §7). All are REGULAR kinds (1000 <= n < 10000 per NIP-01), never the
// NIP-01 ephemeral range: khatru (nak serve) refuses an ephemeral event with
// no matching live subscription and does not buffer it, so an ephemeral kind
// would silently drop auction traffic. KindChat (1442) is his and ours uses it
// for nothing; it is kept only so a chat event stays recognisable by name.
//
// These numbers live here and nowhere else — never as literals through the
// tree. TestKindMapIsRegularRange pins the whole series to the regular range.
const (
	KindCreate       = 1440 // create / root: the auction listing and its supersessions
	KindBid          = 1441 // bid
	KindChat         = 1442 // chat (his; we publish nothing on it)
	KindRefund       = 1443 // refund
	KindSettle       = 1444 // settle
	KindOutcome      = 1445 // outcome / validator verdict
	KindFundingAbort = 1446 // funding abort
	KindStateCommit  = 1447 // state commitment
)

// AuctionKinds is the exported map of the whole series, so a reader (or a
// test) can see and iterate every kind in one place.
var AuctionKinds = map[string]int{
	"create":        KindCreate,
	"bid":           KindBid,
	"chat":          KindChat,
	"refund":        KindRefund,
	"settle":        KindSettle,
	"outcome":       KindOutcome,
	"funding_abort": KindFundingAbort,
	"state_commit":  KindStateCommit,
}

// regularKind: NIP-01's regular range, where relays are expected to STORE the
// event. The auction series must stay inside it (spec §7).
func regularKind(k int) bool { return k >= 1000 && k < 10000 }

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
	// NIP-01: lowercase hex only. Accepting upper case would give one key
	// several pubkey strings and one event several ids (internal audit A4).
	if !lowerHex(e.Pubkey, 64) || !lowerHex(e.ID, 64) || !lowerHex(e.Sig, 128) {
		return errors.New("malformed event: id, pubkey and sig must be lowercase hex")
	}
	h := sha256.Sum256([]byte(e.Serialize()))
	if hex.EncodeToString(h[:]) != e.ID {
		return errors.New("event id mismatch")
	}
	if !schnorrVerifyHash(h[:], e.Pubkey, e.Sig) {
		return errors.New("bad event signature")
	}
	return nil
}

func lowerHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
