/*

SSL Certificate Expiration Monitoring and Alert System

*/

package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net/smtp"
	"os"
	"time"
)

var (
	domains        = []string{"www.cheq.one", "www.xyz.xyz", "api.cheq.one", "console.cheq.one", "content.cheq.one", "devcontent.cheq.one", "grafana.cheq.one", "uat.cheq.one", "uatconsole.cheq.one"}
	senderName     = "Raj Bhatodra"
	senderEmail    = "rajbhatodra842147@gmail.com"
	senderPassword = "oqsr rgvm dukf ubvy"
	hostname       = "smtp.gmail.com"
	port           = 587
	expirationFile = "SSLinfo.json"
)

type DomainInfo struct {
	Domain         string `json:"domainName"`
	ExpirationDate string `json:"expirationDate"`
	DaysRemaining  int    `json:"daysRemaining"`
}

type CertificateInfo struct {
	LastCheckDate string       `json:"lastCheckDate"`
	Domains       []DomainInfo `json:"domains"`
}

func main() {
	fileInfo, err := os.Stat(expirationFile)
	if os.IsNotExist(err) {
		fmt.Println("File does not exist")
		getDomainInfo()
		checkAndSendExpirationAlert()
	} else if err != nil {
		fmt.Println("Error checking file status:", err)
	} else {
		if fileInfo.Size() == 0 {
			fmt.Println("File exists but is empty")
			getDomainInfo()
			checkAndSendExpirationAlert()
		} else {
			fmt.Println("File exists")
			updateMissingDomains()
			checkAndUpdateExpiration()
			checkAndSendExpirationAlert()
		}
	}
}

func getDomainInfo() {
	fmt.Println("Getting Domain Information...")
	certInfo := CertificateInfo{
		LastCheckDate: time.Now().Format("2006-01-02"),
		Domains:       make([]DomainInfo, 0),
	}

	currentTime := time.Now()

	for _, domain := range domains {
		expirationDate, err := getCertificateExpiration(domain + ":443")
		if err != nil {
			fmt.Printf("Error checking certificate for domain %s: %v\n", domain, err)
			continue
		}
		daysRemaining := int(expirationDate.Sub(currentTime).Hours() / 24)
		certInfo.Domains = append(certInfo.Domains, DomainInfo{
			Domain:         domain,
			ExpirationDate: expirationDate.Format("2006-01-02"),
			DaysRemaining:  daysRemaining,
		})
	}

	jsonData, err := json.MarshalIndent(certInfo, "", "    ")
	if err != nil {
		fmt.Println("Error marshaling JSON:", err)
		return
	}

	file, err := os.Create(expirationFile)
	if err != nil {
		fmt.Println("Error creating JSON file:", err)
		return
	}
	defer file.Close()

	_, err = file.Write(jsonData)
	if err != nil {
		fmt.Println("Error writing JSON data to file:", err)
		return
	}

	fmt.Printf("Data saved to %s\n", expirationFile)
}

func updateMissingDomains() {
	file, err := os.OpenFile(expirationFile, os.O_RDWR, 0644)
	if err != nil {
		fmt.Println("Error opening JSON file:", err)
		return
	}
	defer file.Close()

	var certInfo CertificateInfo
	err = json.NewDecoder(file).Decode(&certInfo)
	if err != nil {
		fmt.Println("Error decoding JSON:", err)
		return
	}

	existingDomains := make(map[string]bool)
	for _, domain := range certInfo.Domains {
		existingDomains[domain.Domain] = true
	}

	// Check for missing domains
	missingDomainsUpdated := false
	for _, domain := range domains {
		if _, exists := existingDomains[domain]; !exists {
			expirationDate, err := getCertificateExpiration(domain + ":443")
			if err != nil {
				fmt.Printf("Error checking certificate for domain %s: %v\n", domain, err)
				continue
			}
			daysRemaining := int(time.Until(expirationDate).Hours() / 24)
			fmt.Printf("Adding domain %s with expiration date %s (days remaining: %d)\n", domain, expirationDate.Format("2006-01-02"), daysRemaining)
			certInfo.Domains = append(certInfo.Domains, DomainInfo{
				Domain:         domain,
				ExpirationDate: expirationDate.Format("2006-01-02"),
				DaysRemaining:  daysRemaining,
			})
			missingDomainsUpdated = true
		}
	}

	// Write updated JSON data back to the file if missing domains were updated
	if missingDomainsUpdated {
		file.Seek(0, 0)
		file.Truncate(0) // Clear file contents
		jsonData, err := json.MarshalIndent(certInfo, "", "    ")
		if err != nil {
			fmt.Println("Error marshaling JSON:", err)
			return
		}
		_, err = file.Write(jsonData)
		if err != nil {
			fmt.Println("Error writing JSON data to file:", err)
			return
		}
		fmt.Println("Missing domains updated in the file.")
	}
}

func checkAndUpdateExpiration() {
	file, err := os.OpenFile(expirationFile, os.O_RDWR, 0644)
	if err != nil {
		fmt.Println("Error opening JSON file:", err)
		return
	}
	defer file.Close()

	var certInfo CertificateInfo
	err = json.NewDecoder(file).Decode(&certInfo)
	if err != nil {
		fmt.Println("Error decoding JSON:", err)
		return
	}

	currentTime := time.Now()

	for i, domain := range certInfo.Domains {
		expirationDate, err := time.Parse("2006-01-02", domain.ExpirationDate)
		if err != nil {
			fmt.Printf("Error parsing expiration date for domain %s: %v\n", domain.Domain, err)
			continue
		}

		daysRemaining := expirationDate.Sub(currentTime).Hours() / 24
		if daysRemaining < 10 || daysRemaining < 5 {
			newExpirationDate, err := getCertificateExpiration(domain.Domain + ":443")
			if err != nil {
				fmt.Printf("Error checking certificate for domain %s: %v\n", domain.Domain, err)
				continue
			}

			if newExpirationDate.After(expirationDate) {
				certInfo.Domains[i].ExpirationDate = newExpirationDate.Format("2006-01-02")
				certInfo.Domains[i].DaysRemaining = int(newExpirationDate.Sub(currentTime).Hours() / 24)

				jsonData, err := json.MarshalIndent(certInfo, "", "    ")
				if err != nil {
					fmt.Println("Error marshaling JSON:", err)
					return
				}

				file.Seek(0, 0)
				file.Truncate(0) // Clear file contents
				_, err = file.Write(jsonData)
				if err != nil {
					fmt.Println("Error writing JSON data to file:", err)
					return
				}

				fmt.Printf("Expiration date updated for domain %s. New expiration date: %s\n", domain.Domain, newExpirationDate.Format("2006-01-02"))
			} else {
				fmt.Printf("Expiration date for domain %s remains the same: %s\n", domain.Domain, expirationDate.Format("2006-01-02"))
			}
		}
	}
}

func checkAndSendExpirationAlert() {
	fmt.Println("Checking Expiration Date and Sending Alerts...")
	file, err := os.Open(expirationFile)
	if err != nil {
		fmt.Println("Error opening JSON file:", err)
		return
	}
	defer file.Close()

	var certInfo CertificateInfo
	err = json.NewDecoder(file).Decode(&certInfo)
	if err != nil {
		fmt.Println("Error decoding JSON:", err)
		return
	}

	currentTime := time.Now()
	domainsUpdated := make([]DomainInfo, 0)
	domainsLessThan15Days := make([]DomainInfo, 0)

	for _, domain := range certInfo.Domains {
		expirationDate, err := time.Parse("2006-01-02", domain.ExpirationDate)
		if err != nil {
			fmt.Printf("Error parsing expiration date for domain %s: %v\n", domain.Domain, err)
			continue
		}
		daysRemaining := expirationDate.Sub(currentTime).Hours() / 24
		if daysRemaining > 15 && domain.ExpirationDate != domain.ExpirationDate {
			domainsUpdated = append(domainsUpdated, domain)
		}
		if daysRemaining <= 15 {
			domainsLessThan15Days = append(domainsLessThan15Days, domain)
		}
	}

	if len(domainsLessThan15Days) > 0 {
		fmt.Println("Domains with less than or equal to 15 days remaining:")
		for _, domain := range domainsLessThan15Days {
			fmt.Printf("Domain %s has %d days remaining. Expiration date: %s\n", domain.Domain, domain.DaysRemaining, domain.ExpirationDate)
		}
		sendMail(domainsLessThan15Days, "Expiration")
	} else {
		fmt.Println("No domains found with less than or equal to 15 days remaining.")
	}
}

func getCertificateExpiration(address string) (time.Time, error) {
	conn, err := tls.Dial("tcp", address, &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		return time.Time{}, err
	}
	defer conn.Close()

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return time.Time{}, fmt.Errorf("no certificates found")
	}
	return certs[0].NotAfter, nil
}

func sendMail(expiringDomains []DomainInfo, mailType string) {
	auth := smtp.PlainAuth("", senderEmail, senderPassword, hostname)

	recipients := []string{"er.learning14@gmail.com", "devcenter14@gmail.com"}

	message := "From: " + senderName + " <" + senderEmail + ">\r\n" +
		"To: " + recipients[0] + "\r\n" +
		"Subject: SSL " + mailType + " Alert\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: text/html; charset=utf-8\r\n" +
		"\r\n" +
		"<html><head><style>" +
		".domain-info {margin-bottom: 20px;}" +
		".domain-name, .expiration-date, .days-remaining {margin-left: 10px; font-weight: bold;}" +
		"</style></head><body>" +
		"<h3>Hello Team,</h3>" +
		"<span class=\"domain-name\">We're writing to remind you about the upcoming " + mailType + " of your domain. Please review the details below:</span><br>"

	for _, domain := range expiringDomains {
		message += "<div class=\"domain-info\">" +
			"<span class=\"domain-name\">Domain Name:</span> <a style='color:red; font-weight: bold; text-decoration: none;'>" + domain.Domain + "</a><br>" +
			"<span class=\"expiration-date\">Expiration Date:</span> <span class=\"expiration-date\">" + domain.ExpirationDate + "</span><br>" +
			"<span class=\"days-remaining\">Days Remaining:</span> <span class=\"days-remaining\">" + fmt.Sprint(domain.DaysRemaining) + "</span><br>" +
			"</div>"
	}

	message += "<h4>Best regards,<br> " + senderName + "</h4></body></html>"

	err := smtp.SendMail(hostname+":"+fmt.Sprint(port), auth, senderEmail, recipients, []byte(message))
	if err != nil {
		log.Printf("Failed to send email: %v", err)
		return
	}

	log.Printf("Email sent successfully with expiring domains: %v", expiringDomains)
}
