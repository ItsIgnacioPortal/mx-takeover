package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"sync"

	"github.com/mailgun/mailgun-go/v3"

	"log"
	"os"
	"strings"
	"time"
	tld "github.com/jpillora/go-tld"
	"github.com/likexian/whois"
	whoisparser "github.com/likexian/whois-parser"
	"github.com/miekg/dns"
	"github.com/projectdiscovery/retryabledns"
)

var (
	worker         *int
	throttle       *int
	help           *bool
	expr_day       *int
	mailgun_api    *string
	check_whois    *bool
	verbose        *bool
	only_mx        *bool
	output         *string
	mutex          sync.Mutex
	urls           []string
	record_info    = make(map[string][]string)
)

const colorReset = "\033[0m"
const colorYellow = "\033[33m"
const colorRed = "\033[31m"
const colorCyan = "\033[36m"
const colorGreen = "\033[32m"

func main() {

	info("test1")

	const usage = `Usage: ./mx-takeover [--mailgun-api APIKEY] [--check-whois] [--expire-day DAYS] [--show-only-mx] [--verbose] [--workers NUMBER-OF-WORKERS] [--throttle MILISECONDS] [--output /path/to/file]
Example: cat domains.txt | mx-takeover
  -m, --mailgun-api string
      mailgun api for automatic domain takeover

  -c, --check-whois
      Check whois for detecting unregistered mx domain or domains that will expire soon

  -e, --expire-day
      Estimated days for expiration
      (Default: 30)

  -s, --show-only-mx
      Only show targets which have MX records

  -v, --verbose
      Print all logs

  -w, --workers INT
      Number of workers
      (Default: 5)

  -t, --throttle INT
      Number of miliseconds to wait between each request
      (Default: 200)

  -h, --help
      Display this message
`

	mailgun_api = flag.String("mailgun-api", "", "mailgun api for automatic domain takeover")
	mailgun_api = flag.String("m", "", "mailgun api for automatic domain takeover")
	check_whois = flag.Bool("check-whois", false, "Check whois for detecting unregistered mx domain or domains that will expire soon")
	check_whois = flag.Bool("c", false, "Check whois for detecting unregistered mx domain or domains that will expire soon")
	expr_day = flag.Int("expire-day", 30, "Estimated days for expiration")
	expr_day = flag.Int("e", 30, "Estimated days for expiration")
	only_mx = flag.Bool("show-only-mx", false, "Only show targets which have MX records")
	only_mx = flag.Bool("s", false, "Only show targets which have MX records")
	verbose = flag.Bool("verbose", false, "Print all logs")
	verbose = flag.Bool("v", false, "Print all logs")
	worker = flag.Int("workers", 8, "Number of workers")
	worker = flag.Int("w", 8, "Number of workers")
	throttle = flag.Int("throttle", 200, "Number of miliseconds to wait between each request")
	throttle = flag.Int("t", 200, "Number of miliseconds to wait between each request")
	output = flag.String("output", "", "Save output to file as JSON")
	output = flag.String("o", "", "Save output to file as JSON")

	printBanner()
	flag.Usage = func() { fmt.Print(usage) }
	flag.Parse()

	if *verbose {
		printConf()
	}

	fi, _ := os.Stdin.Stat()
	if fi.Mode()&os.ModeNamedPipe == 0 {
		nonFatalError("No data found in pipe. urls must given using pipe!")
		os.Exit(1)
	} else {
		readFromStdin()
	}

	info("Scan Starting Time: " + time.Now().Format("2006-01-02 15:04:05"))

	if *mailgun_api == "" {
		warning("Mailgun-api was not provided. You should register domain to mailgun manually")
	}

	if *check_whois == false {
		warning("Check-whois argument was not provided. It will not checked whois lookup against MX domains that found.")
	}

	len_url := len(urls)
	if (len_url==0){
		info("0 domains will be scanned.")
	} else if(len_url==1){
		info("1 domain will be scanned.")
	} else {
		info(string(len_url) +" domains will be scanned.")
	}
	


	var waitgroup sync.WaitGroup
	waitgroup.Add(len_url);

	//foreach domain in urls...
	for _, domain := range urls {
		//start goroutine
		go func(){
			getDNSRecord(domain)
			waitgroup.Done();
		}();
	}
	
	//wait until all goroutines finish
	waitgroup.Wait();

	/*
	wp := workerpool.New(*worker)

	for id, domain := range urls {
		domain := domain
		wp.Submit(func() {
			getDNSRecord(id, domain)
		})
	}

	wp.StopWait()
	*/

	defer info("End Time: " + time.Now().Format("2006-01-02 15:04:05"))

	if *output != "" {
		defer writeToFile(*output, record_info)
	}

	if *only_mx {
		defer scanSummary()
	}

	defer whoisMXDomain(record_info)
	if *check_whois {
		defer info("Domains that expire in less than " + string(*expr_day) + " days")
	}
}

func readFromStdin() {
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Split(bufio.ScanLines)

	for scanner.Scan() {
		u := scanner.Text()
		if strings.HasPrefix(u, "https://") {
			url := strings.ReplaceAll(u, "https://", "")
			urls = append(urls, url)

		} else if strings.HasPrefix(u, "http://") {
			url := strings.ReplaceAll(u, "http://", "")
			urls = append(urls, url)
		} else {
			continue
		}
	}
}

func getDNSRecord(domain string) {
	resolvers := []string{"1.1.1.1:53", "8.8.8.8:53", "8.8.4.4:53", "1.0.0.1:53", "208.67.222.222:53"}
	retries := 2
	hostname := domain
	dnsClient := retryabledns.New(resolvers, retries)
	_, err := dnsClient.Resolve(hostname)
	if err != nil {
		warning(hostname + ": skipping...")
	}

	dnsResponses, err := dnsClient.Query(hostname, dns.TypeMX)
	if err != nil {
		warning(hostname + ": skipping...")
	}

	if *verbose {
		log.Println(domain, "MX", dnsResponses.MX)
	}

	if len(dnsResponses.MX) > 0 {
		if *only_mx {
			log.Println(domain, "MX", dnsResponses.MX)
		}
		if checkMXForMailgun(domain, dnsResponses.MX) {
			if *mailgun_api != "" {
				_, err := checkTakeover(domain, *mailgun_api)
				if err != nil {
					api_error := strings.ReplaceAll(err.Error(), "\n", "")
					if strings.Contains(api_error, "Error: ") {
						nonFatalError("Mailgun API Response -> " + strings.Split(api_error, "Error: ")[1])
					} else {
						nonFatalError(api_error)
					}
				} else {
					success("Domain reclaimed successfully! :: " + domain + "\n")
				}
			}
		} else {
			if *check_whois {
				parseMXDomain(domain, dnsResponses.MX)
			}
		}
	}

	//throttle
	time.Sleep(time.Millisecond * time.Duration(*throttle));
}

func checkMXForMailgun(domain string, mxs []string) bool {
	mailgun_mx := [2]string{"mxa.mailgun.org", "mxb.mailgun.org"}
	for _, s := range mxs {
		for _, m := range mailgun_mx {
			if s == m {
				success("Possible Takeover Found! :: " + domain +" MX " + m)
				return true
			}
		}
	}
	return false
}

func checkTakeover(domain, apiKey string) (mailgun.DomainResponse, error) {
	mg := mailgun.NewMailgun(domain, apiKey)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*30)
	defer cancel()

	return mg.CreateDomain(ctx, domain, &mailgun.CreateDomainOptions{
		SpamAction: mailgun.SpamActionTag,
		Wildcard:   false,
	})
}

// find mx domain. (sub.mail.google.com -> google.com)
func parseMXDomain(domain string, mxlist []string) {
	for _, mxd := range mxlist {
		// for parsing correctly added http:// schema.
		u, _ := tld.Parse("http://" + mxd)
		mx_domain := u.Domain + "." + u.TLD
		mutex.Lock()
		if !contains(record_info[mx_domain], domain) {
			record_info[mx_domain] = append(record_info[mx_domain], domain)
		}
		mutex.Unlock()
	}
}

func whoisMXDomain(domains map[string][]string) {
	for mx_domain, dmn := range domains {
		resp_whois, err := whois.Whois(mx_domain)
		if err == nil {
			if result, err := whoisparser.Parse(resp_whois); err == nil {
				if result.Domain.ExpirationDate != "" {
					expireMXDomain(mx_domain, result.Domain.ExpirationDate, dmn)
				}
			} else if err.Error() == "whoisparser: domain is not found" {
				success("Unregistered MX domain was detected! " + strings.Join(dmn," ") + " MX " + mx_domain)
			} else {
				fmt.Println("Error Detected!", err)
			}
		}
	}
}

func contains(domains []string, domain string) bool {
	for _, d := range domains {
		if d == domain {
			return true
		}
	}
	return false
}

func expireMXDomain(mx_domain, expire_date string, dmn []string) {
	date := time.Now()
	format := "2006-01-02T15:04:05Z"
	then, _ := time.Parse(format, expire_date)
	diff := then.Sub(date)
	days_remain := int(diff.Hours() / 24)
	len_dmn := len(dmn)
	if days_remain < *expr_day {
		success("" + mx_domain + " will be expired after [" + string(days_remain) + "] days. It being used by " + string(len_dmn) + " diffirent domain. Expire Time: [" + expire_date + "]. Domains that used by this mx:") // number of days
		fmt.Println(dmn)
	}
}

func scanSummary() {
	for mx, domains := range record_info {
		fmt.Println("%s being used %d different domains. %s mx record being used by these domains : %s \n", mx, len(domains), mx, domains)
	}
}

func writeToFile(filename string, data map[string][]string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()
	map_to_json, err := json.Marshal(data)
	if err != nil {
		fmt.Println("Error: ", err.Error())
	} else {
		_, err = io.WriteString(file, string(map_to_json))
		if err != nil {
			return err
		}
	}
	info("Scan results was saved to " + filename)
	return file.Sync()
}

func printConf() {
	fmt.Println(`
_____________________________________________

Worker      	: %d
Max Expire Day	: %d
Check Whois  	: %t
Show Only MX  	: %t
Verbose      	: %t
Output File  	: %s
_____________________________________________

`, *worker, *expr_day, *check_whois, *only_mx, *verbose, *output)
}

func printBanner() {
	fmt.Println(`
                     _        _                                                                                                       
 _ __ ___ __  __    | |_ __ _| | _____  _____   _____ _ __ 
| '_ ' _ \\ \/ /____| __/ _' | |/ / _ \/ _ \ \ / / _ \ '__|
| | | | | |>  <_____| || (_| |   <  __/ (_) \ V /  __/ |   
|_| |_| |_/_/\_\     \__\__,_|_|\_\___|\___/ \_/ \___|_|   
														
hunting misconfigured MX records
 `)
}


func crash(message string, err error) {
	fmt.Print(string(colorRed) + "[FATAL]: " + message + string(colorReset) + "\n")
	panic(err)
}

func nonFatalError(message string) {
	fmt.Print(string(colorRed) + "[ERROR]: " + message + string(colorReset) + "\n")
}

func warning(message string) {
	fmt.Print(string(colorYellow) + "[WARNING]: " + message + string(colorReset) + "\n")
}

func info(message string){
	fmt.Print(string(colorCyan) + "[-] " + message + string(colorReset) + "\n")
}

func success(message string){
	fmt.Print(string(colorGreen) + "[+] " + message + string(colorReset) + "\n")
}