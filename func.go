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
	"github.com/pkg/errors"
)

func main() {
	if _, b := os.LookupEnv("FN_LISTENER"); !b {
		myHandler(context.Background(), os.Stdin, os.Stdout)
		return
	}
	fdk.Handle(fdk.HandlerFunc(myHandler))
}

func getConfigurationProvider() common.ConfigurationProvider {
	cp, err := auth.ResourcePrincipalConfigurationProvider()
	if err != nil {
		fmt.Println(err)
		return common.DefaultConfigProvider()
	}
	return cp
}

func getEnvOrPanic(key string) string {
	if value, found := os.LookupEnv(key); found {
		return value
	}
	panic("Environment variable not set: " + key)
}

func getLiveCerts(cp common.ConfigurationProvider, ns, bn, certArchive string) (map[string]map[string]string, error) {
	osc, err := objectstorage.NewObjectStorageClientWithConfigurationProvider(cp)
	if err != nil {
		panic(err)
	}
	_, err = osc.HeadObject(context.Background(), objectstorage.HeadObjectRequest{
		NamespaceName: common.String(ns),
		BucketName:    common.String(bn),
		ObjectName:    common.String(certArchive),
	})
	if err != nil {
		return nil, errors.Wrapf(err, "Unable to find certbot archive: /n/%s/b/%s/o/%s", ns, bn, certArchive)
	}
	fmt.Println("** DOWNLOADING CERTIFICATE ARCHIVE **")
	osresp, err := osc.GetObject(context.Background(), objectstorage.GetObjectRequest{
		NamespaceName: common.String(ns),
		BucketName:    common.String(bn),
		ObjectName:    common.String(certArchive),
	})
	if err != nil {
		return nil, errors.Wrap(err, "Failed to download archive")
	}
	zr, err := gzip.NewReader(osresp.Content)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to create gzip reader")
	}
	defer osresp.Content.Close()
	defer zr.Close()
	tr := tar.NewReader(zr)
	pems := make(map[string]map[string]string)
	live := make(map[string]map[string]string)
	buf := new(strings.Builder)
	fmt.Println("** PROCESSING PEM FILES **")
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			err = nil
			break // End of archive
		}

		if err != nil {
			return nil, errors.Wrap(err, "Failed reading tar")
		}

		// process PEM files
		if strings.HasSuffix(hdr.Name, ".pem") {
			// examples:
			// ".../archive/<domain>/fullchain1.pem"
			// ".../live/<domain>/fullchain.pem"
			pemSplit := strings.Split(hdr.Name, "/")
			pemFile := pemSplit[len(pemSplit)-1]
			pemDomain := pemSplit[len(pemSplit)-2]
			pemType := pemSplit[len(pemSplit)-3]
			fmt.Println(pemType + "/" + pemDomain + "/" + pemFile)

			switch pemType {
			case "archive":
				// archive directory contains PEM contents
				// store these in a map
				buf.Reset()
				if _, err := io.Copy(buf, tr); err != nil {
					return nil, errors.Wrap(err, "Failed reading PEM contents from tar")
				}
				if pems[pemDomain] == nil {
					pems[pemDomain] = make(map[string]string)
				}
				pems[pemDomain][pemFile] = buf.String()
			case "live":
				// live directory contains symlinks to archive file
				// store link target to resolve later
				if live[pemDomain] == nil {
					live[pemDomain] = make(map[string]string)
				}
				live[pemDomain][pemFile] = hdr.Linkname
			}
		}
	}

	// resolve link target to copy PEM contents from archive
	for pemDomain, pemDomainMap := range live {
		for pemFile, pemLink := range pemDomainMap {
			pemSplit := strings.Split(pemLink, "/")
			live[pemDomain][pemFile] = pems[pemDomain][pemSplit[len(pemSplit)-1]]
		}
	}

	return live, nil
}

func myHandler(ctx context.Context, in io.Reader, out io.Writer) {
	fmt.Println("** LBCERT FUNCTION **")

	cp := getConfigurationProvider()
	lbOcid := getEnvOrPanic("LBCERT_FN_LB_OCID")
	ns := getEnvOrPanic("LBCERT_FN_OS_NS")
	bn := getEnvOrPanic("LBCERT_FN_OS_BN")
	archivePrefix := getEnvOrPanic("LBCERT_FN_ARCHIVE_PREFIX")
	domain := getEnvOrPanic("LBCERT_FN_DOMAIN")
	certArchive := archivePrefix + "-" + domain + ".tar.gz"

	live, err := getLiveCerts(cp, ns, bn, certArchive)
	if err != nil {
		panic(err)
	}

	cert := live[domain]["fullchain.pem"]
	if len(cert) == 0 {
		panic(fmt.Sprintf("Unable to find certificate %s/fullchain.pem in archive", domain))
	}
	fmt.Println(cert)
	privkey := live[domain]["privkey.pem"]
	if len(privkey) == 0 {
		panic(fmt.Sprintf("Unable to find private key %s/privkey.pem in archive", domain))
	}
	fmt.Println(privkey)

	lb, err := loadbalancer.NewLoadBalancerClientWithConfigurationProvider(cp)
	if err != nil {
		panic(err)
	}
	resp, err := lb.GetLoadBalancer(context.Background(), loadbalancer.GetLoadBalancerRequest{
		LoadBalancerId: common.String(lbOcid),
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
