package main

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/incidrthreat/shodan"
	"github.com/mattermost/mattermost-server/v5/model"
	"github.com/mattermost/mattermost-server/v5/plugin"
)

// CommandHelp displays command info
const CommandHelp = "## **_Mattermost Shodan Plugin - Command Help_**\n" +
	"#### Search Commands\n" +
	"* |/shodan search <ip>| - Searches shodan with provided ip\n" +
	"***\n" +
	"#### Scan Commands\n" +
	"* |/shodan scan <ip>| - Initiates a scan with provided ip\n" +
	"* |/shodan scanstatus <id>| - Returns scan status\n" +
	"* |/shodan protocols| - Returns a list of all protocols scannable with Shodan\n" +
	"***\n" +
	"#### DNS Commands\n" +
	"* |/shodan dnslookup <hostname>| - Returns IPv4 Address of provided hostname\n" +
	"* |/shodan dnsinfo <hostname>| - DNS info from provided hostname\n" +
	"* |/shodan dnsreverse <ip>| - Hostname resolution from provided IP\n" +
	"***\n" +
	"#### Misc Commands\n" +
	"* |/shodan honeyscore <ip>| - Is that host a honeypot? Scale of 0.0 to 1.0\n" +
	"* |/shodan apistatus| - Returns the status of how many Query & Scan Credits remain\n"

// InitCommand ...
func getCommand() *model.Command {
	return &model.Command{
		Trigger:          "shodan",
		DisplayName:      "ShodanBot",
		Description:      "Integration with Shodan API",
		AutoComplete:     true,
		AutoCompleteDesc: "Available commands: search, scan, scanstatus, protocols, dnslookup, dnsinfo, dnsreverse, honeyscore, apistatus, help",
		AutoCompleteHint: "[command] [parameter]",
	}
}

func (p *Plugin) postCommandResponse(args *model.CommandArgs, text string) {
	post := &model.Post{
		UserId:    p.BotUserID,
		ChannelId: args.ChannelId,
		Message:   text,
	}
	_ = p.API.SendEphemeralPost(args.UserId, post)
}

// ExecuteCommand ...
func (p *Plugin) ExecuteCommand(c *plugin.Context, args *model.CommandArgs) (*model.CommandResponse, *model.AppError) {

	// Variables for commands
	// IP address regex
	reIP, _ := regexp.Compile(`^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$`)
	// assigns configuration to config var
	config := p.getConfiguration()
	// removes `[` and `]` in data
	nobraces := strings.NewReplacer("[", "", "]", "")
	split := strings.Fields(args.Command)
	// Empty Vars
	action := ""
	parameter := ""
	// assigns ShodanAPI (supplied in plugin settings) to shodanAPI var
	shodanAPI := shodan.Configure(config.ShodanAPI)
	restAPI := shodanAPI.RestAPI()
	ctx := context.Background()

	if len(split) > 1 {
		action = split[1]
	}
	if len(split) > 2 {
		parameter = split[2]
	}

	if split[0] != "/shodan" {
		return &model.CommandResponse{}, nil
	}

	// Switch-Case for all /shodan actions
	switch action {

	// Displays the help menu
	case "help":
		text := strings.Replace(CommandHelp, "|", "`", -1)
		p.postCommandResponse(args, text)
		return &model.CommandResponse{}, nil

	// Search Methods
	// Search Host Information
	case "search":
		p.ShodanHostSearch(args, parameter)
		return &model.CommandResponse{}, nil

	// On-Demand Scan Methods
	// Protocols Case
	case "protocols":
		if len(parameter) >= 1 {
			p.postCommandResponse(args, fmt.Sprintf("This command has no additional syntax. Please remove `%v` from your command and try again.", parameter))
			return &model.CommandResponse{}, nil
		}
		res, _ := restAPI.Scan().Protocols(ctx)
		data := make(map[string]interface{})

		err := json.Unmarshal([]byte(res), &data)
		if err != nil {
			return &model.CommandResponse{}, nil
		}

		protocols := []string{}

		for protocol := range data {
			protocols = append(protocols, protocol)
		}

		sort.Strings(protocols)

		resp := fmt.Sprint("| **_Protocol_** | **_Description_** |\n|:-|:-|\n")

		for _, value := range protocols {
			resp += fmt.Sprintf("| %v | %v |\n", value, data[value])
		}
		p.postCommandResponse(args, resp)
		return &model.CommandResponse{}, nil

	// Scan Case
	case "scan":
		// uses golang shodan api to send POST request
		res, _ := restAPI.Scan().Scan(ctx, []string{parameter})
		var data map[string]interface{}
		// Unmarshals POST request response into data map
		json.Unmarshal([]byte(res), &data)

		creds, _ := strconv.Atoi(fmt.Sprint(data["credits_left"]))

		resp := "#### Scan Started\n"
		resp += fmt.Sprintf("Scan ID: `%v`\n", data["id"])
		resp += fmt.Sprintf("* Scan credits remaining: %d\n", int(creds)-1)
		resp += fmt.Sprint("\n\nTo check the status of your scan: `/shodan scanstatus <id>`")

		p.postCommandResponse(args, resp)
		return &model.CommandResponse{}, nil
	// Scan Status Case
	case "scanstatus":
		res, _ := restAPI.Scan().ScanStatus(ctx, parameter)
		var data map[string]interface{}

		json.Unmarshal([]byte(res), &data)

		if len(fmt.Sprint(data["error"])) > 5 { // data[error] will either be "<nil>" if empty or "Scan not found"
			resp := "#### Scan Status\n"
			resp += fmt.Sprintf("Scan ID `%v` not found", parameter)
			p.postCommandResponse(args, resp)
		} else {
			resp := "#### Scan Status\n"
			resp += fmt.Sprintf("Scan ID: `%v`\n", data["id"])
			resp += fmt.Sprintf("* Scan started at: %v\n", data["created"])
			resp += fmt.Sprintf("* Status: %v\n", data["status"])

			p.postCommandResponse(args, resp)
		}

		return &model.CommandResponse{}, nil

	// DNS Methods
	// DNS Information Case
	case "dnsinfo":
		res, _ := restAPI.DNS().DomainInfo(ctx, parameter)

		//var data map[string]interface{}
		//
		//json.Unmarshal([]byte(res), &data)
		//

		p.postCommandResponse(args, res)
		return &model.CommandResponse{}, nil
	// DNS Lookup Case
	case "dnslookup":
		res, _ := restAPI.DNS().Lookup(ctx, parameter)

		var data map[string]interface{}

		json.Unmarshal([]byte(res), &data)

		resp := "#### DNS Lookup - results\n"
		resp += fmt.Sprintf("`%v`'s IP:\n", parameter)
		resp += fmt.Sprintf("* %v\n", data[parameter])

		p.postCommandResponse(args, resp)
		return &model.CommandResponse{}, nil
	// DNS Reverse Lookup Case
	case "dnsreverse":
		res, _ := restAPI.DNS().ReverseLookup(ctx, parameter)

		var data map[string]interface{}

		json.Unmarshal([]byte(res), &data)

		hostname := fmt.Sprint(data[parameter])

		if hostname == "<nil>" {
			resp := "#### Reverse DNS - results\n"
			resp += fmt.Sprintf("`%v` does not resolve to a hostname, try a different IP.\n", parameter)
			p.postCommandResponse(args, resp)
		} else {
			resp := "#### Reverse DNS - results\n"
			resp += fmt.Sprintf("%v resolves to %v\n", parameter, nobraces.Replace(hostname))
			p.postCommandResponse(args, resp)
		}

		return &model.CommandResponse{}, nil

	// Misc Methods
	// Calculate honeypot score from 0,0 to 1.0
	case "honeyscore":
		parameter = strings.Trim(parameter, " ")
		// regex to check if proper IP
		if reIP.MatchString(parameter) {
			res, _ := restAPI.Experimental().Honeyscore(ctx, parameter)
			// Catching the error
			var data map[string]interface{}
			json.Unmarshal([]byte(res), &data)

			if data["error"] == "No information available for that IP." {
				resp := "#### Honeypot Probability Score\n"
				resp += fmt.Sprintf("No Data found on `%v`\n", parameter)
				p.postCommandResponse(args, resp)
			} else {
				resp := "#### Honeypot Probability Score\n"
				resp += fmt.Sprint("Ranging from 0.0 (not a honeypot) to 1.0 (is a honeypot).\n")
				resp += fmt.Sprintf("%v scored a %v\n", parameter, res)
				p.postCommandResponse(args, resp)
			}
		} else {
			p.postCommandResponse(args, fmt.Sprintf("%v is not a valid IP address.\n", parameter))
		}
		return &model.CommandResponse{}, nil
	// Grabs the API Status, returning # of Query & Scan credits remain
	case "apistatus":
		if len(parameter) >= 1 {
			p.postCommandResponse(args, fmt.Sprintf("This command has no additional syntax. Please remove `%v` from your command and try again.", parameter))
			return &model.CommandResponse{}, nil
		}

		res, _ := restAPI.APIStatus().ApiInfo(ctx)

		var data map[string]interface{}

		json.Unmarshal([]byte(res), &data)

		resp := "#### API Status Information\n"
		resp += fmt.Sprintf("* Remaining Query Credits: %v\n", data["query_credits"])
		resp += fmt.Sprintf("* Remaining Scan Credits: %v\n", data["scan_credits"])
		resp += fmt.Sprintf("* Currently monitoring %v IP(s)\n", data["monitored_ips"])
		p.postCommandResponse(args, resp)

		return &model.CommandResponse{}, nil
	}

	p.postCommandResponse(args, fmt.Sprintf("`/shodan %v` is not a valid command.  Check `/shodan help` to see all available options/syntax and try again.\n", action))

	return &model.CommandResponse{}, nil
}

// ShodanHostSearch ...
func (p *Plugin) ShodanHostSearch(args *model.CommandArgs, ip string) {
	reIP, _ := regexp.Compile(`^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$`)
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
			resp += fmt.Sprintf("| %v |  |\n|:-|:-|\n", ip)
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
			if data["hostnames"] != "[]" {
				resp += fmt.Sprintf("| Hostname(s) | %v |\n", nobraces.Replace(strings.Join(hostnames, ", ")))
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
