package codec_test

import (
	"testing"

	"github.com/ErenOzgu/rtp-quality/internal/codec"
)

func TestStaticTable(t *testing.T) {
	for pt, want := range map[uint8]struct {
		name  string
		clock int
		model bool
	}{0: {"PCMU", 8000, true}, 8: {"PCMA", 8000, true}, 18: {"G729", 8000, true}, 9: {"G722", 8000, false}, 13: {"CN", 8000, false}} {
		i := codec.Lookup(pt, nil)
		if i.Name != want.name || i.ClockRate != want.clock || i.HasModel != want.model || !i.Known {
			t.Errorf("PT %d: %+v", pt, i)
		}
	}
	if codec.Lookup(13, nil).Audio {
		t.Error("comfort noise counted as audio")
	}
}

func TestUnknownDynamicType(t *testing.T) {
	i := codec.Lookup(111, nil)
	if i.Known || i.Name != "PT111" || i.ClockRate != 8000 || !i.Audio || i.HasModel {
		t.Errorf("%+v", i)
	}
	if codec.Lookup(50, nil).Audio {
		t.Error("an unassigned static type should not be assumed to be audio")
	}
}

func TestParse(t *testing.T) {
	pt, i, err := codec.Parse("96=opus/48000")
	if err != nil || pt != 96 || i.Name != "opus" || i.ClockRate != 48000 || !i.Audio || !i.Known || i.HasModel {
		t.Errorf("%d %+v %v", pt, i, err)
	}
	_, ev, err := codec.Parse("101=telephone-event/8000")
	if err != nil || ev.Audio {
		t.Errorf("telephone-event: %+v %v", ev, err)
	}
	// Describing a payload type as what it already is keeps the E-model values.
	_, pcmu, err := codec.Parse("0=PCMU/8000")
	if err != nil || !pcmu.HasModel {
		t.Errorf("PCMU: %+v %v", pcmu, err)
	}
	// A dynamic type that carries PCMU gets no E-model values unless said so; this is documented.
	_, dyn, _ := codec.Parse("96=PCMU/8000")
	if dyn.Name != "PCMU" {
		t.Errorf("%+v", dyn)
	}
	for _, bad := range []string{"", "96", "96=opus", "x=opus/8000", "200=opus/8000", "96=opus/0", "96=opus/-8000"} {
		if _, _, err := codec.Parse(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
