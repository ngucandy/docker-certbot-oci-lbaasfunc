package main

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	fdk "github.com/fnproject/fdk-go"
	"github.com/oracle/oci-go-sdk/v27/common"
	"github.com/oracle/oci-go-sdk/v27/common/auth"
	"github.com/oracle/oci-go-sdk/v27/loadbalancer"
	"github.com/oracle/oci-go-sdk/v27/objectstorage"
)

const (
	loadBalancerID = "ocid1.loadbalancer.oc1.ca-montreal-1.aaaaaaaargd3kdbuw6rnwwuesrtrrymlbcjuk2es63b6vvnxp4aozj4vefpa"
	ns             = "ocisateam"
	bn             = "andynguyen_certbot_bucket"
	certbotArchive = "certbot-archive-oci-ateam.com.tar.gz"
)

func main() {
	if _, b := os.LookupEnv("FN_LISTENER"); !b {
		myHandler(nil, nil, nil)
		return
	}
	fdk.Handle(fdk.HandlerFunc(myHandler))
}

func myHandler(ctx context.Context, in io.Reader, out io.Writer) {
	fmt.Println("** LBAAS **")
	var cp common.ConfigurationProvider
	cp, err := auth.ResourcePrincipalConfigurationProvider()
	if err != nil {
		fmt.Println(err)
		cp = common.DefaultConfigProvider()
	}

	osc, err := objectstorage.NewObjectStorageClientWithConfigurationProvider(cp)
	if err != nil {
		panic(err)
	}
	_, err = osc.HeadObject(context.Background(), objectstorage.HeadObjectRequest{
		NamespaceName: common.String(ns),
		BucketName:    common.String(bn),
		ObjectName:    common.String(certbotArchive),
	})
	if err != nil {
		fmt.Printf("Unable to find certbot archive: /n/%s/b/%s/o/%s\n", ns, bn, certbotArchive)
		return
	}
	fmt.Println("** DOWNLOADING CERTIFICATE ARCHIVE **")
	osresp, err := osc.GetObject(context.Background(), objectstorage.GetObjectRequest{
		NamespaceName: common.String(ns),
		BucketName:    common.String(bn),
		ObjectName:    common.String(certbotArchive),
	})
	if err != nil {
		panic(err)
	}
	zr, err := gzip.NewReader(osresp.Content)
	if err != nil {
		panic(err)
	}
	defer osresp.Content.Close()
	defer zr.Close()
	tr := tar.NewReader(zr)
	pems := make(map[string]string)
	live := make(map[string]string)
	buf := new(strings.Builder)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break // End of archive
		}
		if err != nil {
			panic(err)
		}
		if strings.HasSuffix(hdr.Name, ".pem") {
			k := strings.SplitN(hdr.Name, "/", 3)[2]
			if hdr.Typeflag == tar.TypeSymlink {
				live[k] = strings.SplitN(hdr.Linkname, "/", 3)[2]
				continue
			}
			buf.Reset()
			if _, err := io.Copy(buf, tr); err != nil {
				panic(err)
			}
			pems[k] = buf.String()
		}
	}
	var cert string
	var privkey string
	for k, v := range live {
		if strings.HasSuffix(k, "fullchain.pem") {
			cert = pems[v]
		} else if strings.HasSuffix(k, "privkey.pem") {
			privkey = pems[v]
		}
	}
	if len(cert) == 0 {
		panic("Unable to find certificate in archive")
	}
	if len(privkey) == 0 {
		panic("Unable to find private key in archive")
	}
	fmt.Println(cert)
	fmt.Println(privkey)

	lb, err := loadbalancer.NewLoadBalancerClientWithConfigurationProvider(cp)
	if err != nil {
		panic(err)
	}
	resp, err := lb.GetLoadBalancer(context.Background(), loadbalancer.GetLoadBalancerRequest{
		LoadBalancerId: common.String(loadBalancerID),
	})
	if err != nil {
		panic(err)
	}

	for _, value := range resp.LoadBalancer.Listeners {
		if value.SslConfiguration != nil {
			b, err := json.Marshal(value)
			if err != nil {
				panic(err)
			}
			uld := loadbalancer.UpdateListenerDetails{}
			err = json.Unmarshal(b, &uld)
			if err != nil {
				panic(err)
			}
			uld.SslConfiguration.CertificateName = common.String("new_certificate")
			fmt.Println(uld)
		}
	}

	//		json.NewEncoder(out).Encode(&msg)
}
