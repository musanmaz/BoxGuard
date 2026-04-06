package report

import (
	"encoding/json"
	"errors"
	"fmt"

	"boxguard/pkg/model"
)

type Reporter interface{ Emit(model.ScanResult) error }

type jsonReporter struct{}

func (j *jsonReporter) Emit(res model.ScanResult) error {
	b, err := json.MarshalIndent(res, "", " ")
	if err != nil {
		return err
	}
	fmt.Println(string(b))
	return nil
}

func New(kind string) (Reporter, error) {
	switch kind {
	case "table":
		return &tableReporter{}, nil
	case "json":
		return &jsonReporter{}, nil
	default:
		return nil, errors.New("invalid output format: use table or json")
	}
}
