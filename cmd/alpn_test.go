package cmd

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
)

func TestFillDetails_ALPN(t *testing.T) {
	cases := []struct {
		enableHTTP2 bool
		want        string
	}{
		{true, "h2"},
		{false, "http/1.1"},
	}
	for _, tc := range cases {
		t.Run(tc.want, func(t *testing.T) {
			resetGlobalFlags()
			flagInsecure = true
			ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte("ok"))
			}))
			ts.EnableHTTP2 = tc.enableHTTP2
			ts.StartTLS()
			defer ts.Close()

			host, portStr, _ := net.SplitHostPort(ts.Listener.Addr().String())
			port, _ := strconv.Atoi(portStr)
			r := &TLSScanResult{}
			if err := fillDetails(r, host, port); err != nil {
				t.Fatalf("fillDetails error: %v", err)
			}
			if r.NegotiatedProto != tc.want {
				t.Fatalf("expected %s got %s", tc.want, r.NegotiatedProto)
			}
		})
	}
}
