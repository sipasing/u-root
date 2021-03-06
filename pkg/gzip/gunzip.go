// Copyright 2017-2018 the u-root Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package gzip

import (
	"io"

	"github.com/klauspost/pgzip"
)

// Decompress takes gzip compressed input from io.Reader and expands it using pgzip
// to io.Writer. Data is read in blocksize (KB) chunks using upto the number of
// CPU cores specified.
func Decompress(r io.Reader, w io.Writer, blocksize int, processes int) error {
	zr, err := pgzip.NewReaderN(r, blocksize*1024, processes)
	if err != nil {
		return err
	}

	if _, err := io.Copy(w, zr); err != nil {
		zr.Close()
		return err
	}

	return zr.Close()
}
