// Copyright 2021-2024 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package encoding

import (
	"reflect"

	cbor "github.com/fxamacker/cbor/v2"
)

type CBORTagEntry struct {
	Type interface{}
	Tag  uint64
}

func InitCBOREncMode(tagEntries ...CBORTagEntry) (en cbor.EncMode, err error) {
	encOpt := cbor.EncOptions{
		IndefLength: cbor.IndefLengthForbidden,
		TimeTag:     cbor.EncTagRequired,
	}
	return encOpt.EncModeWithTags(ccaTags(tagEntries))
}

func InitCBORDecMode(tagEntries ...CBORTagEntry) (dm cbor.DecMode, err error) {
	decOpt := cbor.DecOptions{
		IndefLength: cbor.IndefLengthForbidden,
	}
	return decOpt.DecModeWithTags(ccaTags(tagEntries))
}

func ccaTags(tagEntries []CBORTagEntry) cbor.TagSet {
	opts := cbor.TagOptions{
		EncTag: cbor.EncTagRequired,
		DecTag: cbor.DecTagRequired,
	}

	tags := cbor.NewTagSet()

	for _, entry := range tagEntries {
		if err := tags.Add(opts, reflect.TypeOf(entry.Type), entry.Tag); err != nil {
			panic(err)
		}
	}

	return tags
}
