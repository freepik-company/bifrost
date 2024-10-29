package httpserver

import "io"

type ReadInformer struct {
	Reader  io.Reader
	ReadErr error
}

type WriteInformer struct {
	Writer   io.Writer
	WriteErr error
}

func (rw *ReadInformer) Read(p []byte) (int, error) {
	n, err := rw.Reader.Read(p)
	if err != nil {
		rw.ReadErr = err
	}
	return n, err
}

func (rw *WriteInformer) Write(p []byte) (int, error) {
	n, err := rw.Writer.Write(p)
	if err != nil {
		rw.WriteErr = err
	}
	return n, err
}
