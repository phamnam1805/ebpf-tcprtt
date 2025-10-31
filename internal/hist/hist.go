package hist

import (
    "bytes"
	"fmt"
	"strings"
    "encoding/binary"
)

const MaxSlot = 27

type Hist struct {
	Latency uint64
	Cnt 	uint64 
	Slots 	[MaxSlot]int32
	_       [4]byte
}

func UnmarshalBinary(data []byte) (*Hist, error) {
    var hist Hist
    reader := bytes.NewReader(data)
    if err := binary.Read(reader, binary.LittleEndian, &hist); err != nil {
        return nil, err
    }
    return &hist, nil
}

func (h *Hist) PrintInfo() error {
	fmt.Printf("Latency = %d\n", h.Latency)
	fmt.Printf("Cnt = %d\n\n", h.Cnt)
	fmt.Printf("     (unit)              : count    distribution\n")

	// Find slot having maximum count to scale the diagram
	var maxCount int32
	var lastSlotNonZero int
	for i, c := range h.Slots {
		if c > maxCount {
			maxCount = c
		}
		if c > 0 {
			lastSlotNonZero = i
		}
	}
	if maxCount == 0 {
		maxCount = 1 
	}

	// Print histogram
	low := 0
	for i, c := range h.Slots {
		if i > lastSlotNonZero {
			break
		}
		high := (1 << i) - 1
		if i > 0 {
			low = (1 << (i - 1))
		}

		barLen := int(float64(c) / float64(maxCount) * 40.0) 
		bar := strings.Repeat("*", barLen)
		fmt.Printf("%10d -> %-10d : %-8d |%-40s|\n", low, high, c, bar)
	}
	return nil
}
