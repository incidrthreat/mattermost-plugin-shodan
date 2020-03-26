package main

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/incidrthreat/shodan"
	"github.com/mattermost/mattermost-server/v5/model"
)

const (
	ipaddress = `^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$`
)

// HostInfo ...
func (p *Plugin) HostInfo(args *model.CommandArgs, ip string) {
	reIP, _ := regexp.Compile(ipaddress)
	// removes spaces around parameter input
	config := p.getConfiguration()

	nobraces := strings.NewReplacer("[", "", "]", "")

	// assigns ShodanAPI (supplied in plugin settings) to shodanAPI var
	shodanAPI := shodan.Configure(config.ShodanAPI)
	restAPI := shodanAPI.RestAPI()
	ctx := context.Background()
	// regex to check if proper IP
	if reIP.MatchString(ip) {
		res, _ := restAPI.Search().HostInfo(ctx, ip, false)

		var data map[string]interface{}
		json.Unmarshal([]byte(res), &data)
		if res != "Invalid IP" {
			resp := "#### Search Results\n"
			resp += fmt.Sprintf("| Host | %v |\n|:-|:-|\n", ip)
			if data["city"] != nil {
				resp += fmt.Sprintf("| City | %v |\n", data["city"])
			}
			resp += fmt.Sprintf("| Country | %v |\n", data["country_name"])
			resp += fmt.Sprintf("| Organization | %v |\n", data["org"])
			resp += fmt.Sprintf("| ISP | %v |\n", data["isp"])
			// converts interface to []string
			ports := strings.Fields(fmt.Sprint(data["ports"]))
			// Adds ports in as comma seperated string
			resp += fmt.Sprintf("| Port(s) | %v |\n", nobraces.Replace(strings.Join(ports, ", ")))
			hostnames := strings.Fields(fmt.Sprint(data["hostnames"]))
			jhostnames := nobraces.Replace(strings.Join(hostnames, ", "))
			if jhostnames != "" {
				resp += fmt.Sprintf("| Hostname(s) | %v |\n", jhostnames)
			}
			resp += fmt.Sprintf("\n\n\nMore information on Shodan at: [https://www.shodan.io/host/%v](https://www.shodan.io/host/%v)", ip, ip)

			p.postCommandResponse(args, resp)
		} else {
			p.postCommandResponse(args, fmt.Sprintf("#### No Data found on %v", ip))
		}
	} else {
		p.postCommandResponse(args, fmt.Sprintf("%v is not a valid IP address", ip))
	}
}

// AllPorts ...
func (p *Plugin) AllPorts(args *model.CommandArgs) {
	config := p.getConfiguration()
	shodanAPI := shodan.Configure(config.ShodanAPI)
	restAPI := shodanAPI.RestAPI()

	nobraces := strings.NewReplacer("[", "", "]", "")

	ctx := context.Background()

	res, _ := restAPI.Search().Ports(ctx)

	resp := fmt.Sprint("| **_All ports Shodan is crawling_** |\n|:-|\n")
	ports := strings.Split(res, ", ")
	resp += fmt.Sprintf("| %v |", nobraces.Replace(strings.Join(ports, ", ")))
	p.postCommandResponse(args, resp)
}
