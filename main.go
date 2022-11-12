package cfbp

import (
	"context"
	"crypto/tls"
	"errors"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
)

func Url(target string) bool {
	u, err := url.Parse(target)

	if err != nil || u.Scheme == "" || u.Host == "" {
		return false
	}

	return true
}

func CloudFlareIsPresent(target string, client *http.Client) bool {
	// Check for a typical Cloudflare response
	resp, err := client.Get(target)
	if err != nil {
		log.Fatal("Could not GET target when performing Cloudflare checks")
	}

	if resp.StatusCode == 503 && strings.Contains(resp.Header.Get("Server"), "cloudflare") {
		return true
	}

	return false
}

func Initialize(client *http.Client) {
	// If a proxy is defined, skip TLS verification.
	// We do this as it seems likely you are testing via ZAP/Burp/etc
	var tr http.Transport
	if os.Getenv("HTTP_PROXY") != "" || os.Getenv("HTTPS_PROXY") != "" {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
		tr.Proxy = http.ProxyFromEnvironment
	}

	// Initialize an empty cookie jar. It will be populated later with Cloudflare cookie
	cookieJar, _ := cookiejar.New(nil)

	client.Transport = &tr
	client.Jar = cookieJar
}

func BakeCookies(target string, cfToken string) (*url.URL, []*http.Cookie) {
	u, _ := url.Parse(target)
	d := "." + u.Host
	var cookies []*http.Cookie
	cfCookie := &http.Cookie{
		Name:   "cf_clearance",
		Value:  cfToken,
		Path:   "/",
		Domain: d,
	}
	cookies = append(cookies, cfCookie)
	cookieURL, _ := url.Parse(target)

	return cookieURL, cookies
}

func GetCloudFlareClearanceCookie(client *http.Client, agent string, target string) error {
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		// Ignore certificate errors (for use with proxy testing)
		chromedp.Flag("ignore-certificate-errors", "1"),
		// User-Agent MUST match what your tooling uses
		chromedp.UserAgent(agent),
	)
	allocCtx, cancel := chromedp.NewExecAllocator(context.Background(), opts...)
	defer cancel()

	// Create the chrome instance
	ctx, cancel := chromedp.NewContext(
		allocCtx,
		chromedp.WithLogf(log.Printf),
	)
	defer cancel()

	// Challenges should be solved in ~5 seconds but can be slower. Timeout at 30.
	ctx, cancel = context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	// Listen for the Cloudflare cookie
	cookieReceiverChan := make(chan string, 1)
	defer close(cookieReceiverChan)

	// Fetch the login page and wait until CF challenge is solved.
	err := chromedp.Run(ctx,
		chromedp.Navigate(target),
		chromedp.WaitNotPresent(`Checking your browser`, chromedp.BySearch),
		extractCookie(cookieReceiverChan),
	)
	if err != nil {
		if err == context.DeadlineExceeded {
			return errors.New("Context deadline exceeded trying to grab cookie using chromedp")
		}
		return err
	}

	// block the program until the cloud flare cookie is received, or .WaitVisible times out looking for login-pane
	cfToken := <-cookieReceiverChan

	log.Printf("[*] Grabbed Cloudflare token: %s", cfToken)

	// Finally, build up the cookie jar with the required token
	cookieURL, cookies := BakeCookies(target, cfToken)
	client.Jar.SetCookies(cookieURL, cookies)

	return nil
}

func extractCookie(c chan string) chromedp.Action {
	return chromedp.ActionFunc(func(ctx context.Context) error {
		cookies, err := network.GetAllCookies().Do(ctx)
		if err != nil {
			return err
		}
		for _, cookie := range cookies {
			if strings.ToLower(cookie.Name) == "cf_clearance" {
				// if we find a proper cookie, put the value on the receiving channel
				c <- cookie.Value
			}
		}
		return nil
	})
}

// ConfigureCfClient should be called directly, using a URL string as the target
// and a second string for the User-Agent to pass. User-Agent must match what
// you use in your tooling for subsequent requests, per Cloudflare.
// Pass in your own http.Client that will receive CloudFlares'
// (cf_clearance) if the site is protected.
func ConfigureClient(client *http.Client, target string, agent string) error {
	// Initialize the client with the things we need to bypass cloudflare
	Initialize(client)

	// Validate the target URL
	if Url(target) == false {
		return errors.New("could not parse the target URL")
	}

	// Check if target is even protected by Cloudflare. If not, just return the
	// client as-is.
	if CloudFlareIsPresent(target, client) == false {
		log.Println("[*] Target not protected by Cloudflare.")
		return nil
	}

	log.Println("[!] Target is protected by Cloudflare, bypassing...")

	return GetCloudFlareClearanceCookie(client, agent, target)

}
