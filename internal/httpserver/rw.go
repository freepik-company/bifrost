package httpserver

import "io"

type ReadWriteInformer struct {
	Reader   io.Reader
	Writer   io.Writer
	ReadErr  error
	WriteErr error
}

func (rw *ReadWriteInformer) Read(p []byte) (int, error) {
	n, err := rw.Reader.Read(p)
	if err != nil {
		rw.ReadErr = err
	}
	return n, err
}

func (rw *ReadWriteInformer) Write(p []byte) (int, error) {
	n, err := rw.Writer.Write(p)
	if err != nil {
		rw.WriteErr = err
	}
	return n, err
}
