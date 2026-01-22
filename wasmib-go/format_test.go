package wasmib

import (
	"testing"
)

func TestFormatTimeTicks(t *testing.T) {
	tests := []struct {
		value uint32
		want  string
	}{
		{0, "0:00:00.00"},
		{100, "0:00:01.00"},    // 1 second
		{150, "0:00:01.50"},    // 1.5 seconds
		{6000, "0:01:00.00"},   // 1 minute
		{360000, "1:00:00.00"}, // 1 hour
		{8640000, "1 day, 0:00:00.00"},
		{17280000, "2 days, 0:00:00.00"},
		{8643661, "1 day, 0:00:36.61"},
		{36061, "0:06:00.61"},
		{99, "0:00:00.99"},
		{4294967295, "497 days, 2:27:52.95"}, // max uint32
	}

	for _, tt := range tests {
		got := FormatTimeTicks(tt.value)
		if got != tt.want {
			t.Errorf("FormatTimeTicks(%d) = %q, want %q", tt.value, got, tt.want)
		}
	}
}

func TestFormatOctetString_NoHint(t *testing.T) {
	tests := []struct {
		name  string
		value []byte
		want  string
	}{
		{"empty", []byte{}, ""},
		{"printable ascii", []byte("hello world"), "hello world"},
		{"binary data", []byte{0x00, 0x1a, 0x2b, 0x3c}, "00:1a:2b:3c"},
		{"mixed with control", []byte{0x48, 0x69, 0x00}, "48:69:00"},
		{"single byte", []byte{0xff}, "ff"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FormatOctetString(tt.value, "", HexLower)
			if got != tt.want {
				t.Errorf("FormatOctetString(%v, \"\", HexLower) = %q, want %q", tt.value, got, tt.want)
			}
		})
	}
}

func TestApplyOctetHint(t *testing.T) {
	// Use HexUpper to match reference implementation for these tests
	hexCase := HexUpper

	cases := []struct {
		name   string
		hint   string
		data   []byte
		result string
	}{
		{
			name:   "InetAddressIPv4 - 1d.1d.1d.1d",
			hint:   "1d.1d.1d.1d",
			data:   []byte{192, 168, 1, 1},
			result: "192.168.1.1",
		},
		{
			name:   "InetAddressIPv4z - 1d.1d.1d.1d%4d (zone ID)",
			hint:   "1d.1d.1d.1d%4d",
			data:   []byte{192, 168, 1, 1, 0, 0, 0, 3},
			result: "192.168.1.1%3",
		},
		{
			name:   "PhysAddress (MAC) - 1x: with implicit repetition",
			hint:   "1x:",
			data:   []byte{0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e},
			result: "00:1A:2B:3C:4D:5E",
		},
		{
			name:   "InetAddressIPv6 - 2x:2x:2x:2x:2x:2x:2x:2x",
			hint:   "2x:2x:2x:2x:2x:2x:2x:2x",
			data:   []byte{0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
			result: "2001:0DB8:0000:0000:0000:0000:0000:0001",
		},
		{
			name:   "InetAddressIPv6z - IPv6 with zone ID",
			hint:   "2x:2x:2x:2x:2x:2x:2x:2x%4d",
			data:   []byte{0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x05},
			result: "FE80:0000:0000:0000:0000:0000:0000:0001%5",
		},
		{
			name:   "DisplayString - 255a",
			hint:   "255a",
			data:   []byte("Hello, World!"),
			result: "Hello, World!",
		},
		{
			name:   "Simple decimal - 1d",
			hint:   "1d",
			data:   []byte{42},
			result: "42",
		},
		{
			name:   "Multi-byte decimal - 4d (DNS-SERVER-MIB)",
			hint:   "4d",
			data:   []byte{0x00, 0x01, 0x00, 0x00},
			result: "65536",
		},
		{
			name:   "Octal format - 1o",
			hint:   "1o",
			data:   []byte{8},
			result: "10",
		},
		{
			name:   "Hex with dash separator - 1x-",
			hint:   "1x-",
			data:   []byte{0xaa, 0xbb, 0xcc},
			result: "AA-BB-CC",
		},
		{
			name:   "Star prefix repeat",
			hint:   "*1x:",
			data:   []byte{3, 0xaa, 0xbb, 0xcc},
			result: "AA:BB:CC",
		},
		{
			name:   "Star prefix with terminator",
			hint:   "*1d./1d",
			data:   []byte{3, 10, 20, 30, 40},
			result: "10.20.30/40",
		},
		{
			name:   "Trailing separator suppressed",
			hint:   "1d.",
			data:   []byte{1, 2, 3},
			result: "1.2.3",
		},
		{
			name:   "DateAndTime-like format - 2d-1d-1d,1d:1d:1d.1d",
			hint:   "2d-1d-1d,1d:1d:1d.1d",
			data:   []byte{0x07, 0xE6, 8, 15, 8, 1, 15, 0},
			result: "2022-8-15,8:1:15.0",
		},
		{
			name:   "Data shorter than spec",
			hint:   "1d.1d.1d.1d",
			data:   []byte{10, 20},
			result: "10.20",
		},
		{
			name:   "UTF-8 format - 10t",
			hint:   "10t",
			data:   []byte("hello"),
			result: "hello",
		},
		{
			name:   "UUID format - 4x-2x-2x-1x1x-6x",
			hint:   "4x-2x-2x-1x1x-6x",
			data:   []byte{0x12, 0x34, 0x56, 0x78, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
			result: "12345678-ABCD-EF01-2345-001122334455",
		},
		{
			name:   "IPv4 with prefix - 1d.1d.1d.1d/1d",
			hint:   "1d.1d.1d.1d/1d",
			data:   []byte{10, 0, 0, 0, 24},
			result: "10.0.0.0/24",
		},
		{
			name:   "2-digit take value - 10d",
			hint:   "10d",
			data:   []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
			result: "1",
		},
		{
			name:   "Zero-padded hex output",
			hint:   "1x",
			data:   []byte{0x0f},
			result: "0F",
		},
		{
			name:   "Single byte with trailing separator suppressed",
			hint:   "1d.",
			data:   []byte{42},
			result: "42",
		},
		{
			name:   "Implicit repetition with longer data",
			hint:   "1d.",
			data:   []byte{1, 2, 3, 4, 5},
			result: "1.2.3.4.5",
		},
		{
			name:   "Last spec repeats after fixed prefix",
			hint:   "1d-1d.",
			data:   []byte{1, 2, 3, 4, 5, 6},
			result: "1-2.3.4.5.6",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			result, ok := applyOctetHint(c.hint, c.data, hexCase)
			if !ok {
				t.Errorf("applyOctetHint(%q, %v, HexUpper) returned ok=false, want ok=true", c.hint, c.data)
				return
			}
			if result != c.result {
				t.Errorf("applyOctetHint(%q, %v, HexUpper) = %q, want %q", c.hint, c.data, result, c.result)
			}
		})
	}
}

func TestApplyOctetHintErrors(t *testing.T) {
	cases := []struct {
		name string
		hint string
		data []byte
	}{
		{
			name: "Empty hint",
			hint: "",
			data: []byte{1, 2, 3},
		},
		{
			name: "Empty data",
			hint: "1d",
			data: []byte{},
		},
		{
			name: "Invalid format character",
			hint: "1z",
			data: []byte{1, 2, 3},
		},
		{
			name: "Missing format character",
			hint: "1",
			data: []byte{1, 2, 3},
		},
		{
			name: "Missing take value",
			hint: "d",
			data: []byte{1, 2, 3},
		},
		{
			name: "Decimal take too large for uint64",
			hint: "9d",
			data: []byte{0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		},
		{
			name: "Octal take too large for uint64",
			hint: "9o",
			data: []byte{0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, ok := applyOctetHint(c.hint, c.data, HexLower)
			if ok {
				t.Errorf("applyOctetHint(%q, %v, HexLower) returned ok=true, want ok=false for invalid hint", c.hint, c.data)
			}
		})
	}
}

func TestApplyOctetHintZeroWidthValid(t *testing.T) {
	hexCase := HexUpper

	cases := []struct {
		name   string
		hint   string
		data   []byte
		result string
	}{
		{
			name:   "Zero-width bracket prefix with trailing content",
			hint:   "0a[1a]1a",
			data:   []byte{0x41, 0x42},
			result: "[A]B",
		},
		{
			name:   "Zero-width prefix trailing suppressed",
			hint:   "0a[1a",
			data:   []byte{0x41},
			result: "[A",
		},
		{
			name:   "TransportAddressIPv6 style simplified",
			hint:   "0a[2x]0a:2d",
			data:   []byte{0x20, 0x01, 0x00, 0x50},
			result: "[2001]:80",
		},
		{
			name:   "Zero-width prefix only",
			hint:   "0a<1d-1d-1d",
			data:   []byte{1, 2, 3},
			result: "<1-2-3",
		},
		{
			name:   "Zero-width mid-hint",
			hint:   "1d-0a.1d",
			data:   []byte{10, 20},
			result: "10-.20",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			result, ok := applyOctetHint(c.hint, c.data, hexCase)
			if !ok {
				t.Errorf("applyOctetHint(%q, %v, HexUpper) returned ok=false, want ok=true", c.hint, c.data)
				return
			}
			if result != c.result {
				t.Errorf("applyOctetHint(%q, %v, HexUpper) = %q, want %q", c.hint, c.data, result, c.result)
			}
		})
	}
}

func TestApplyOctetHintZeroWidthInvalid(t *testing.T) {
	cases := []struct {
		name string
		hint string
		data []byte
	}{
		{
			name: "Zero-width hex trailing",
			hint: "0x",
			data: []byte{0x41, 0x42},
		},
		{
			name: "Zero-width decimal trailing",
			hint: "0d",
			data: []byte{1, 2, 3},
		},
		{
			name: "Zero-width octal trailing",
			hint: "0o",
			data: []byte{8, 9},
		},
		{
			name: "Zero-width ascii trailing",
			hint: "0a.",
			data: []byte{1, 2, 3},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, ok := applyOctetHint(c.hint, c.data, HexLower)
			if ok {
				t.Errorf("applyOctetHint(%q, %v, HexLower) returned ok=true, want ok=false for zero-width trailing", c.hint, c.data)
			}
		})
	}
}

func TestFormatOctetString_HexCase(t *testing.T) {
	value := []byte{0x0a, 0x1b, 0x2c}

	// Test lowercase
	got := FormatOctetString(value, "", HexLower)
	if got != "0a:1b:2c" {
		t.Errorf("HexLower: got %q, want \"0a:1b:2c\"", got)
	}

	// Test uppercase
	got = FormatOctetString(value, "", HexUpper)
	if got != "0A:1B:2C" {
		t.Errorf("HexUpper: got %q, want \"0A:1B:2C\"", got)
	}

	// Test with hint
	got = FormatOctetString(value, "1x:", HexUpper)
	if got != "0A:1B:2C" {
		t.Errorf("HexUpper with hint: got %q, want \"0A:1B:2C\"", got)
	}
}

func TestFormatBits(t *testing.T) {
	m := &Model{
		strings: []string{"bit0Name", "bit3Name", "bit7Name"},
	}

	tests := []struct {
		name    string
		value   []byte
		bitDefs []BitDef
		want    string
	}{
		{
			name:  "no bits set",
			value: []byte{0x00},
			want:  "(none)",
		},
		{
			name:  "empty value",
			value: []byte{},
			want:  "(none)",
		},
		{
			name:  "bit 0 set (MSB)",
			value: []byte{0x80},
			bitDefs: []BitDef{
				{Position: 0, Name: 1},
			},
			want: "{bit0Name}",
		},
		{
			name:  "bits 0 and 7 set",
			value: []byte{0x81},
			bitDefs: []BitDef{
				{Position: 0, Name: 1},
				{Position: 7, Name: 3},
			},
			want: "{bit0Name, bit7Name}",
		},
		{
			name:  "unknown bit position",
			value: []byte{0x40},
			want:  "{bit1}",
		},
		{
			name:  "multi-byte with bit 8",
			value: []byte{0x00, 0x80},
			want:  "{bit8}",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			obj := &Object{
				InlineBits: tt.bitDefs,
			}
			got := FormatBits(m, obj, tt.value)
			if got != tt.want {
				t.Errorf("FormatBits = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestFormatInteger(t *testing.T) {
	m := &Model{
		strings: []string{"up", "down", "testing", "seconds"},
		types: []Type{
			{
				EnumValues: []EnumValue{
					{Value: 1, Name: 1},
					{Value: 2, Name: 2},
					{Value: 3, Name: 3},
				},
			},
		},
	}

	tests := []struct {
		name       string
		value      int64
		typeID     uint32
		inlineEnum []EnumValue
		units      uint32
		want       string
	}{
		{
			name:   "plain integer",
			value:  42,
			typeID: 0,
			want:   "42",
		},
		{
			name:   "enum from type",
			value:  1,
			typeID: 1,
			want:   "up(1)",
		},
		{
			name:   "enum value 2",
			value:  2,
			typeID: 1,
			want:   "down(2)",
		},
		{
			name:   "non-enum value with enum type",
			value:  99,
			typeID: 1,
			want:   "99",
		},
		{
			name:  "inline enum overrides type",
			value: 1,
			inlineEnum: []EnumValue{
				{Value: 1, Name: 2},
			},
			typeID: 1,
			want:   "down(1)",
		},
		{
			name:   "with units",
			value:  100,
			typeID: 0,
			units:  4,
			want:   "100 seconds",
		},
		{
			name:   "enum with units",
			value:  1,
			typeID: 1,
			units:  4,
			want:   "up(1) seconds",
		},
		{
			name:   "negative value",
			value:  -50,
			typeID: 0,
			want:   "-50",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var obj *Object
			if tt.typeID != 0 || len(tt.inlineEnum) > 0 || tt.units != 0 {
				obj = &Object{
					TypeID:     tt.typeID,
					InlineEnum: tt.inlineEnum,
					Units:      tt.units,
				}
			}
			got := FormatInteger(m, obj, tt.value)
			if got != tt.want {
				t.Errorf("FormatInteger = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestFormatOID(t *testing.T) {
	t.Run("no model", func(t *testing.T) {
		oid := []uint32{1, 3, 6, 1, 2, 1}
		got := FormatOID(nil, oid)
		if got != "1.3.6.1.2.1" {
			t.Errorf("FormatOID(nil, %v) = %q, want \"1.3.6.1.2.1\"", oid, got)
		}
	})

	t.Run("empty oid", func(t *testing.T) {
		got := FormatOID(nil, []uint32{})
		if got != "" {
			t.Errorf("FormatOID(nil, []) = %q, want \"\"", got)
		}
	})
}

func TestIsPrintableASCII(t *testing.T) {
	tests := []struct {
		data []byte
		want bool
	}{
		{[]byte("hello"), true},
		{[]byte("Hello World 123!"), true},
		{[]byte{0x20, 0x7E}, true},
		{[]byte{0x19}, false},
		{[]byte{0x7F}, false},
		{[]byte{0x00}, false},
		{[]byte("hello\x00"), false},
		{[]byte{}, true},
	}

	for _, tt := range tests {
		got := isPrintableASCII(tt.data)
		if got != tt.want {
			t.Errorf("isPrintableASCII(%v) = %v, want %v", tt.data, got, tt.want)
		}
	}
}

func TestFormatValue(t *testing.T) {
	m := &Model{
		strings: []string{"seconds", "enabled", "disabled"},
		types: []Type{
			{Base: BaseTypeInteger32},
			{Base: BaseTypeTimeTicks},
			{
				Base: BaseTypeBits,
				BitDefs: []BitDef{
					{Position: 0, Name: 2},
				},
			},
			{
				Base: BaseTypeOctetString,
				Hint: 1,
			},
		},
	}

	t.Run("int64 value", func(t *testing.T) {
		got := FormatValue(m, nil, int64(42))
		if got != "42" {
			t.Errorf("FormatValue(int64(42)) = %q, want \"42\"", got)
		}
	})

	t.Run("uint32 timeticks", func(t *testing.T) {
		obj := &Object{TypeID: 2}
		got := FormatValue(m, obj, uint32(100))
		if got != "0:00:01.00" {
			t.Errorf("FormatValue(timeticks 100) = %q, want \"0:00:01.00\"", got)
		}
	})

	t.Run("[]byte as bits", func(t *testing.T) {
		obj := &Object{TypeID: 3}
		got := FormatValue(m, obj, []byte{0x80})
		if got != "{enabled}" {
			t.Errorf("FormatValue(bits 0x80) = %q, want \"{enabled}\"", got)
		}
	})

	t.Run("[]uint32 as oid", func(t *testing.T) {
		got := FormatValue(m, nil, []uint32{1, 3, 6, 1})
		if got != "1.3.6.1" {
			t.Errorf("FormatValue(oid) = %q, want \"1.3.6.1\"", got)
		}
	})

	t.Run("nil value", func(t *testing.T) {
		got := FormatValue(m, nil, nil)
		if got != "" {
			t.Errorf("FormatValue(nil) = %q, want \"\"", got)
		}
	})

	t.Run("string as octet string", func(t *testing.T) {
		obj := &Object{TypeID: 1}
		got := FormatValue(m, obj, "hello")
		if got != "hello" {
			t.Errorf("FormatValue(string \"hello\") = %q, want \"hello\"", got)
		}
	})
}

func TestFormatBits_WithTypeLevel(t *testing.T) {
	m := &Model{
		strings: []string{"adminStatus", "operStatus"},
		types: []Type{
			{
				BitDefs: []BitDef{
					{Position: 0, Name: 1},
					{Position: 1, Name: 2},
				},
			},
		},
	}

	obj := &Object{
		TypeID: 1,
	}

	got := FormatBits(m, obj, []byte{0xC0})
	want := "{adminStatus, operStatus}"
	if got != want {
		t.Errorf("FormatBits with type-level defs = %q, want %q", got, want)
	}
}

func TestFormatInteger_NilObject(t *testing.T) {
	m := &Model{}
	got := FormatInteger(m, nil, 42)
	if got != "42" {
		t.Errorf("FormatInteger(nil obj) = %q, want \"42\"", got)
	}
}

func TestHexTable(t *testing.T) {
	if hexTable(HexLower) != hexLower {
		t.Error("hexTable(HexLower) should return hexLower")
	}

	if hexTable(HexUpper) != hexUpper {
		t.Error("hexTable(HexUpper) should return hexUpper")
	}
}
