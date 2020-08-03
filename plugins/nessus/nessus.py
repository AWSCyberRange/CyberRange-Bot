# !awscyberrange prototype

import os, requests, json, re
from errbot import BotPlugin, botcmd, arg_botcmd

class nessus(BotPlugin):

    @botcmd(split_args_with=None, hidden=True)
    def nessus(self, mess, args):

        if len(args)!=1:
            return("Incorrect number of parameters.  Must either specifcy the CVE number YYYY-####[###] or a digit # for the most recent N CVE's")
            exit()

        # Assign arguments to variables
        answer = "Answer:\r\n"
        arg=args[0]
        if re.match(r'^[\d]{4}\-[\d]{4,7}$', arg): # Specific CVE - response is json
            # url = "http://cve.circl.lu/api/cve/CVE-" + arg
            # try:
            #     response = requests.get(url)
            # except:
            #     return("Could not retrieve page")
            #     exit()

            # json_entry = response.json()
            # if json_entry is None:  #Check to make sure the CVE was valid
            #     return("CVE Not Found.  Check the ID and try again.")

            # print(json_entry)
            # answer+="##ID:  " + str(json_entry["id"]) + "\r\n"
            # answer+="Summary:  " + str(json_entry["summary"]) + "\r\n"
            # answer+="Published:  " + str(json_entry["Published"]) + "\r\n"
            # answer+="Last Modifiedd:  " + str(json_entry["last-modified"]) + "\r\n"
            # answer+="CVSS:  " + str(json_entry["cvss"]) + "\r\n"
            # answer+="References:  " + str(json_entry["references"]) + "\r\n\r\n"

            # query tenable plugins
            # url = "https://www.tenable.com/plugins/search?q=\"" + arg + "\""
            url = "https://www.tenable.com/plugins/api/v1/search?q=%22" + arg + "%22&page=1&sort="
            try:
                response = requests.get(url)
            except:
                return("Could not retrieve page")
                exit()

            print('-------------------')
            print(response)
            
            json_entry = response.json()
            if json_entry is None:  #Check to make sure the CVE was valid
                return("CVE Not Found in Tenable.  Check the ID and try again.")

            print(json_entry)
            results = len(json_entry["data"]["hits"])
            name = "info ["
            for i in range(results):
                name += str(json_entry["data"]["hits"][i]["_source"]["script_name"])
                print("\n=============" + str(i) + "["+ str(results) + "]["+str(range(results)))
                print(str(json_entry["data"]["hits"][i]["_source"]["script_name"])) 
                answer+="## Nessus Plugin ID:  " + str(json_entry["data"]["hits"][i]["_source"]["script_id"]) + "\r\n"
                answer+="## Nessus Plugin Name:  " + str(json_entry["data"]["hits"][i]["_source"]["script_name"]) + "\r\n"


            print("NAME: " + name)
            answer+="## Nessus Plugin ID:  " + str(json_entry["data"]["hits"]) + "\r\n"
            # answer+="Summary:  " + str(json_entry["description"]) + "\r\n"
            # answer+="Published:  " + str(json_entry["Published"]) + "\r\n"
            # answer+="Last Modifiedd:  " + str(json_entry["last-modified"]) + "\r\n"
            # answer+="CVSS:  " + str(json_entry["cvss"]) + "\r\n"
            # answer+="References:  " + str(json_entry["references"]) + "\r\n\r\n"
            print(answer)
            print('-------------------')

        elif re.match(r'^[\d]+$', arg): # Last n CVEs - response is list of json
            url = "http://cve.circl.lu/api/last/" + arg
            try:
                response = requests.get(url)
                print(response)
            except:
                return("Could not retrieve page")
                exit()

            data_list = response.json()
            #iterate over a list of dict entries
            for json_entry in data_list:
                answer+="##ID:  " + str(json_entry["id"]) + "\r\n"
                answer+="Summary:  " + str(json_entry["summary"]) + "\r\n"
                answer+="Published:  " + str(json_entry["Published"]) + "\r\n"
                answer+="Last Modifiedd:  " + str(json_entry["last-modified"]) + "\r\n"
                answer+="CVSS:  " + str(json_entry["cvss"]) + "\r\n"
                answer+="References:  " + str(json_entry["references"]) + "\r\n\r\n"

        else:
            return("Error: Input must be an integer or a CVE number in the format: YYYY-####[###].")

        return(answer)
