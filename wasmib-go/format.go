package wasmib

import (
	"strconv"
	"strings"
)

// HexCase controls uppercase vs lowercase hex output.
type HexCase bool

const (
	// HexLower outputs lowercase hex digits (0a:1b:2c).
	HexLower HexCase = false
	// HexUpper outputs uppercase hex digits (0A:1B:2C).
	HexUpper HexCase = true
)

const (
	hexLower = "0123456789abcdef"
	hexUpper = "0123456789ABCDEF"
)

func hexTable(hexCase HexCase) string {
	if hexCase == HexUpper {
		return hexUpper
	}
	return hexLower
}

// FormatInteger formats an integer value with enum lookup and units.
// If obj or m is nil, returns the plain numeric value.
func FormatInteger(m *Model, obj *Object, value int64) string {
	var enumName string

	// Check inline enum first, then type-level enum
	if m != nil && obj != nil {
		for _, ev := range obj.InlineEnum {
			if ev.Value == value {
				enumName = ev.Name
				break
			}
		}
		if enumName == "" && obj.TypeID != 0 {
			if t := m.GetType(obj.TypeID); t != nil {
				for _, ev := range t.EnumValues {
					if ev.Value == value {
						enumName = ev.Name
						break
					}
				}
			}
		}
	}

	var b strings.Builder
	if enumName != "" {
		b.WriteString(enumName)
		b.WriteByte('(')
		b.WriteString(strconv.FormatInt(value, 10))
		b.WriteByte(')')
	} else {
		b.WriteString(strconv.FormatInt(value, 10))
	}

	// Append units if present
	if obj != nil && obj.Units != "" {
		b.WriteByte(' ')
		b.WriteString(obj.Units)
	}

	return b.String()
}

// applyOctetHint parses an RFC 2579 DISPLAY-HINT string and applies it to
// raw bytes in a single pass.
//
// Returns (result, true) on success, or ("", false) on any parse error.
// The caller should fall back to default formatting when ok is false.
//
// RFC 2579 Section 3.1 defines the octet-format specification:
//   - Optional '*' repeat indicator: first byte of value is repeat count
//   - Octet length: decimal digits specifying bytes to consume per application
//   - Format: 'd' decimal, 'x' hex, 'o' octal, 'a' ASCII, 't' UTF-8
//   - Optional separator: single character after each application
//   - Optional terminator: single character after repeat group (requires '*')
//
// The last format specification repeats until all data is exhausted (implicit
// repetition rule). Trailing separators are suppressed.
func applyOctetHint(hint string, data []byte, hexCase HexCase) (string, bool) {
	if hint == "" || len(data) == 0 {
		return "", false
	}

	hex := hexTable(hexCase)
	var result strings.Builder
	result.Grow(len(data) * 4)

	hintPos := 0
	dataPos := 0

	// Track the start of the last spec for implicit repetition
	lastSpecStart := 0
	// Track whether the last spec consumes data (for infinite loop prevention)
	lastSpecConsumesByte := false

	for dataPos < len(data) {
		specStart := hintPos

		// If we've exhausted the hint, restart from the last spec (implicit repetition)
		if hintPos >= len(hint) {
			// Guard against infinite loop: if last spec doesn't consume data, bail
			if !lastSpecConsumesByte {
				return "", false
			}
			hintPos = lastSpecStart
			specStart = lastSpecStart
		}

		// (1) Optional '*' repeat indicator
		starPrefix := false
		if hintPos < len(hint) && hint[hintPos] == '*' {
			starPrefix = true
			hintPos++
		}

		// (2) Octet length - one or more decimal digits (required)
		if hintPos >= len(hint) || hint[hintPos] < '0' || hint[hintPos] > '9' {
			return "", false
		}

		take := 0
		for hintPos < len(hint) && hint[hintPos] >= '0' && hint[hintPos] <= '9' {
			take = take*10 + int(hint[hintPos]-'0')
			hintPos++
		}

		if take < 0 {
			// Overflow wrapped to negative
			return "", false
		}

		// (3) Format character (required)
		if hintPos >= len(hint) {
			return "", false
		}

		fmtChar := hint[hintPos]
		if fmtChar != 'd' && fmtChar != 'x' && fmtChar != 'o' && fmtChar != 'a' && fmtChar != 't' {
			return "", false
		}
		hintPos++

		// (4) Optional separator
		var sep byte
		hasSep := false
		if hintPos < len(hint) && (hint[hintPos] < '0' || hint[hintPos] > '9') && hint[hintPos] != '*' {
			sep = hint[hintPos]
			hasSep = true
			hintPos++
		}

		// (5) Optional terminator (only valid with starPrefix)
		var term byte
		hasTerm := false
		if starPrefix && hintPos < len(hint) && (hint[hintPos] < '0' || hint[hintPos] > '9') && hint[hintPos] != '*' {
			term = hint[hintPos]
			hasTerm = true
			hintPos++
		}

		// Remember this spec for implicit repetition
		lastSpecStart = specStart
		// A spec consumes data if take > 0, or if starPrefix (consumes repeat count byte)
		lastSpecConsumesByte = (take > 0) || starPrefix

		// Apply the spec to data
		repeatCount := 1
		if starPrefix && dataPos < len(data) {
			repeatCount = int(data[dataPos])
			dataPos++
		}

		for r := 0; r < repeatCount && dataPos < len(data); r++ {
			end := dataPos + take
			if end > len(data) || end < dataPos { // catch overflow
				end = len(data)
			}
			chunk := data[dataPos:end]

			switch fmtChar {
			case 'd':
				if len(chunk) > 8 {
					return "", false
				}
				var val uint64
				for _, b := range chunk {
					val = (val << 8) | uint64(b)
				}
				result.WriteString(strconv.FormatUint(val, 10))
			case 'x':
				for _, v := range chunk {
					result.WriteByte(hex[v>>4])
					result.WriteByte(hex[v&0x0f])
				}
			case 'o':
				if len(chunk) > 8 {
					return "", false
				}
				var val uint64
				for _, b := range chunk {
					val = (val << 8) | uint64(b)
				}
				result.WriteString(strconv.FormatUint(val, 8))
			case 'a', 't':
				result.Write(chunk)
			}
			dataPos = end

			// Emit separator (suppressed if at end of data or before terminator)
			moreData := dataPos < len(data)
			if hasSep && moreData && (!hasTerm || r != repeatCount-1) {
				result.WriteByte(sep)
			}
		}

		// Emit terminator after repeat group
		if hasTerm && dataPos < len(data) {
			result.WriteByte(term)
		}
	}

	return result.String(), true
}

// isPrintableASCII checks if all bytes are printable ASCII (0x20-0x7E).
func isPrintableASCII(data []byte) bool {
	for _, c := range data {
		if c < 0x20 || c > 0x7E {
			return false
		}
	}
	return true
}

// FormatOctetString formats an OCTET STRING value using DISPLAY-HINT.
// If hint is empty or invalid, falls back to hex for binary data or UTF-8 for printable ASCII.
// The hexCase parameter controls whether hex output uses lowercase or uppercase letters.
func FormatOctetString(value []byte, hint string, hexCase HexCase) string {
	if len(value) == 0 {
		return ""
	}

	// Try to apply hint if present
	if hint != "" {
		if result, ok := applyOctetHint(hint, value, hexCase); ok {
			return result
		}
	}

	// Fallback: printable ASCII as string, otherwise hex dump
	if isPrintableASCII(value) {
		return string(value)
	}

	// Hex dump with colon separators
	hex := hexTable(hexCase)
	var b strings.Builder
	for i, c := range value {
		if i > 0 {
			b.WriteByte(':')
		}
		b.WriteByte(hex[c>>4])
		b.WriteByte(hex[c&0x0f])
	}
	return b.String()
}

// FormatBits formats a BITS value with named bit positions.
// SNMP BITS encoding: MSB first (bit 0 = 0x80 of first byte).
// If m is nil, bit positions are shown without names.
func FormatBits(m *Model, obj *Object, value []byte) string {
	if len(value) == 0 {
		return "(none)"
	}

	// Build map of position -> name
	bitNames := make(map[uint32]string)
	if m != nil && obj != nil {
		for _, bd := range obj.InlineBits {
			bitNames[bd.Position] = bd.Name
		}
		if len(bitNames) == 0 && obj.TypeID != 0 {
			if t := m.GetType(obj.TypeID); t != nil {
				for _, bd := range t.BitDefs {
					bitNames[bd.Position] = bd.Name
				}
			}
		}
	}

	// Find set bits
	var setBits []string
	for byteIdx, b := range value {
		for bitInByte := 0; bitInByte < 8; bitInByte++ {
			// SNMP BITS: bit 0 is MSB of first byte
			if b&(0x80>>bitInByte) != 0 {
				position := uint32(byteIdx*8 + bitInByte)
				if name, ok := bitNames[position]; ok && name != "" {
					setBits = append(setBits, name)
				} else {
					setBits = append(setBits, "bit"+strconv.FormatUint(uint64(position), 10))
				}
			}
		}
	}

	if len(setBits) == 0 {
		return "(none)"
	}

	var b strings.Builder
	b.WriteByte('{')
	for i, name := range setBits {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString(name)
	}
	b.WriteByte('}')
	return b.String()
}

// FormatTimeTicks formats a TimeTicks value as human-readable duration.
// Input is centiseconds (1/100th second).
// Output: "N days, H:MM:SS.cc" or "H:MM:SS.cc"
func FormatTimeTicks(value uint32) string {
	centiseconds := uint64(value)
	seconds := centiseconds / 100
	cs := centiseconds % 100

	minutes := seconds / 60
	secs := seconds % 60

	hours := minutes / 60
	mins := minutes % 60

	days := hours / 24
	hrs := hours % 24

	var b strings.Builder
	if days > 0 {
		b.WriteString(strconv.FormatUint(days, 10))
		if days == 1 {
			b.WriteString(" day, ")
		} else {
			b.WriteString(" days, ")
		}
	}

	b.WriteString(strconv.FormatUint(hrs, 10))
	b.WriteByte(':')
	if mins < 10 {
		b.WriteByte('0')
	}
	b.WriteString(strconv.FormatUint(mins, 10))
	b.WriteByte(':')
	if secs < 10 {
		b.WriteByte('0')
	}
	b.WriteString(strconv.FormatUint(secs, 10))
	b.WriteByte('.')
	if cs < 10 {
		b.WriteByte('0')
	}
	b.WriteString(strconv.FormatUint(cs, 10))

	return b.String()
}

// FormatOID formats an OID value as a dotted string with optional name lookup.
func FormatOID(m *Model, value []uint32) string {
	if len(value) == 0 {
		return ""
	}

	var b strings.Builder
	for i, arc := range value {
		if i > 0 {
			b.WriteByte('.')
		}
		b.WriteString(strconv.FormatUint(uint64(arc), 10))
	}

	// Try to find the node name
	if m != nil {
		if node := m.GetNodeByOIDSlice(value); node != nil {
			if len(node.Definitions) > 0 {
				name := node.Definitions[0].Label
				if name != "" {
					b.WriteByte('(')
					b.WriteString(name)
					b.WriteByte(')')
				}
			}
		}
	}

	return b.String()
}

// FormatValue formats any SNMP value based on object type information.
// Dispatches to the appropriate formatter based on base type.
// If m is nil, formatting proceeds with default/unknown type handling.
func FormatValue(m *Model, obj *Object, value any) string {
	if value == nil {
		return ""
	}

	baseType := BaseTypeUnknown
	var hint string

	if m != nil && obj != nil && obj.TypeID != 0 {
		if t := m.GetType(obj.TypeID); t != nil {
			baseType = t.Base
			hint = m.GetEffectiveHint(obj.TypeID)
		}
	}

	switch v := value.(type) {
	case int64:
		return formatIntegerValue(m, obj, baseType, v)
	case int32:
		return formatIntegerValue(m, obj, baseType, int64(v))
	case int:
		return formatIntegerValue(m, obj, baseType, int64(v))
	case uint64:
		return formatUnsignedValue(m, obj, baseType, v)
	case uint32:
		return formatUnsignedValue(m, obj, baseType, uint64(v))
	case uint:
		return formatUnsignedValue(m, obj, baseType, uint64(v))
	case []byte:
		return formatBytesValue(m, obj, baseType, hint, v)
	case string:
		return formatBytesValue(m, obj, baseType, hint, []byte(v))
	case []uint32:
		return FormatOID(m, v)
	default:
		// Unknown type, try to format as string
		return ""
	}
}

func formatIntegerValue(m *Model, obj *Object, baseType BaseType, value int64) string {
	switch baseType {
	case BaseTypeTimeTicks:
		if value >= 0 {
			return FormatTimeTicks(uint32(value))
		}
		return strconv.FormatInt(value, 10)
	case BaseTypeInteger32:
		return FormatInteger(m, obj, value)
	default:
		// For other integer types, just format with units if available
		s := strconv.FormatInt(value, 10)
		if obj != nil && obj.Units != "" {
			s += " " + obj.Units
		}
		return s
	}
}

func formatUnsignedValue(m *Model, obj *Object, baseType BaseType, value uint64) string {
	switch baseType {
	case BaseTypeTimeTicks:
		return FormatTimeTicks(uint32(value))
	case BaseTypeInteger32:
		// Integer32 with unsigned Go value - still check enum
		return FormatInteger(m, obj, int64(value))
	default:
		s := strconv.FormatUint(value, 10)
		if obj != nil && obj.Units != "" {
			s += " " + obj.Units
		}
		return s
	}
}

func formatBytesValue(m *Model, obj *Object, baseType BaseType, hint string, value []byte) string {
	switch baseType {
	case BaseTypeBits:
		return FormatBits(m, obj, value)
	case BaseTypeObjectIdentifier:
		// OID encoded as bytes - decode to arcs
		// BER encoding: each arc is 7-bit encoded with continuation bit
		// First two arcs are encoded as (arc1 * 40 + arc2)
		// This is a simplified decoder for the common case
		if len(value) == 0 {
			return ""
		}
		var arcs []uint32
		if value[0] < 40 {
			arcs = append(arcs, 0, uint32(value[0]))
		} else if value[0] < 80 {
			arcs = append(arcs, 1, uint32(value[0]-40))
		} else {
			arcs = append(arcs, 2, uint32(value[0]-80))
		}
		i := 1
		for i < len(value) {
			var arc uint32
			for i < len(value) {
				arc = arc<<7 | uint32(value[i]&0x7f)
				if value[i]&0x80 == 0 {
					i++
					break
				}
				i++
			}
			arcs = append(arcs, arc)
		}
		return FormatOID(m, arcs)
	default:
		return FormatOctetString(value, hint, HexLower)
	}
}
