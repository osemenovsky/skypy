#!/usr/bin/env python3

import requests
import time
import json
import hashlib
from html.parser import HTMLParser

# TODO: refactor this
# TODO: find out which other features to implement
# TODO: check if everything works okay

class InputParser(HTMLParser):
    """
    HTML parser to get all the input fields values
    """
    def __init__(self):
        super().__init__()
        self.inputs = {}

    def handle_starttag(self, tag, attrs):
        if tag == "input":
            tagdict = {}
            for key, val in attrs:
                tagdict[key] = val
                if key == "name":
                    name = val

            self.inputs[name] = tagdict

    def get_inputs(self):
        """
        Returns a dictionary of inputs
        """
        return(self.inputs)

    def get_attribute(self, tag, attribute):
        """
        Returns given attribute for given input field
        """
        return(self.inputs[tag][attribute])

    def get_value(self, tag):
        """
        Returns a value attribute of given input field
        """
        return(self.inputs[tag]["value"])


class Skype():
    """
    Skype connection object.
    Allows to authenticate login.skype.com, and send messages (by now)
    """
    def __init__(self, username, password):
        """
        Some data shared between functions
        """
        self.urls = {
            "contacts": "api.skype.com",
            "new_contacts": "contacts.skype.com",
            "login": "login.skype.com",
            "messages_old?": "client-s.gateway.messenger.live.com",
            "messages": "bn2-client-s.gateway.messenger.live.com",
        }
        self.session = requests.session()
        self.creds = {"username": username, "password": password}
        self.skypetoken = None
        self.initial = None
        self.parser = InputParser()
        self.lock_and_key_response = ""
        self.k_lock_and_key_appid = "msmsgs@msnmsgr.com"
        self.k_lock_and_key_secret = "Q1P7W2E4J9R8U3S5"
        self.k_client_info = "os=Windows; osVer=8.1; proc=Win32; lcid=en-us; deviceType=1; country=n/a; clientName=swx-skype.com; clientVer=908/1.0.0.20"
        self.k_login_host = "login.skype.com"
        self.k_contacts_host = "api.skype.com"
        self.k_contacts_host = "client-s.gateway.messenger.live.com"

        self.k_status_map = {
          "Online": "AVAILABLE",
          "Offline": "OFFLINE",
          "Idle": "IDLE",
          "Away": "AWAY",
          "Hidden": "INVISIBLE"
        }
        self.registration_token = {}

    def is_authenticated(self):
        """
        Check for authentication and return True if authentication is successful
        """
        self.initial = self.session.get(
                "https://{}/login?method=skype&client_id=578134&redirect_uri=https%3A%2F%2Fweb.skype.com".format(
                self.urls["login"]))

        self.parser.feed(self.initial.content.decode("cp1251")) # Parsing input fields

        if not "skypetoken" in self.parser.get_inputs():
            return(False)
        else:
            return(True)


    def authenticate(self):
        """
        Authenticate in skype's web client.
        """
        auth_headers = {
            "Connection": "close",
            "Accept": "*/*",
            "BehaviorOverride": "redirectAs404",
            "Host": self.urls["login"],
            "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
            "User-Agent": None
        }

        # TODO: Generate timezone values based on system information
        self.creds["timezone_field"] = "+03|00"
        self.creds["pie"] = self.parser.get_value("pie")
        self.creds["etm"] = self.parser.get_value("etm")
        self.creds["js_time"] = str(round(time.time(), 3))
        self.creds["client_id"] = "578134"
        self.creds["redirect_uri"] = "https://web.skype.com/"

        post_payload = {
            "method": "skype",
            "client_id": "578134",
            "redirect_uri": "https://web.skype.com"
        }
        auth_response = self.session.post("https://login.skype.com/login",
            params=post_payload,
            data=self.creds,
            headers=auth_headers,
        )

        self.parser.feed(auth_response.content.decode("cp1251"))

        # Looks for skypetoken and if none found - assumes captcha
        # TODO: Add more error checks if needed
        if not "skypetoken" in self.parser.get_inputs():
            raise Exception("Captcha required. Try logging into web.skype.com and try again.")

        else:
            self.skypetoken = self.parser.get_value("skypetoken")
            return(self.skypetoken)


    def get_registration_token(self):
        """
        Get a registrationToken, which is needed to send messages
        """

        # Thanks EionRobb for this his skypeweb pidgin plugin, 
        # and thanks to commcentral's skype protocol implementation, 
        # They have been a good reference

        if not self.skypetoken:
            raise Exception("Need to authenticate first")

        url = "https://{}/v1/users/ME/endpoints".format(self.urls["messages"])
        headers = {
            "Origin": "https://web.skype.com",
            "skypetoken": "skypetoken={}".format(self.skypetoken)
        }

        # Generation magic sha256 hash
        # TODO: Describe the hash generation mechanism

        # Creating initial values
        # time_value is an integer of current time
        # app_name is pretty self-explanatory
        # app_secret word i took from skype protocol plugin for pidgin (skypeweb)

        time_value = str(int(time.time()))
        app_name = "msmsgs@msnmsgr.com".encode("ascii")
        app_secret_word = "Q1P7W2E4J9R8U3S5".encode("ascii")

        # Creating empty sha256 hash and updating it with
        # current time and secret word and getting half of it's digest
        hash_value = hashlib.sha256()
        hash_value.update(time_value.encode("ascii"))
        hash_value.update(app_secret_word)
        sha_256_hash = hash_value.digest()[:16]

        # Creating a string containing current time and app_name
        # And padding it with zeroes to the length that's a multiple of 8
        new_string = time_value.encode("ascii") + app_name
        if len(new_string) % 8:
            new_string += (b"0" * (8 - (len(new_string) % 8)))

        # Creating two lists for hash parts
        sha_256_parts = []
        new_hash_parts = []

        # Dividing digest to four parts and converting them to integers
        for i in range(4):
            c = int(len(sha_256_hash)/4)
            # Appending initial integer to sha_256_parts list
            sha_256_parts.append(int.from_bytes(
                sha_256_hash[c*i:c*i+c], byteorder='little', signed=False
            ))
            # Appending initial integer to new_hash_parts list
            new_hash_parts.append(sha_256_parts[i])
            # &ing initial integer in sha_256_parts list with 0x7fffffff
            sha_256_parts[i] &= 0x7fffffff

        # Creating two temporary values
        n_high = 0
        n_low = 0

        for i in range(0, int(len(new_string)/4), 2):
            # Here be magic
            # Getting two values by slicing a string, created earlier
            # and converting them to integers
            uint1 = int.from_bytes(
                new_string[i * 4:i * 4 + 4],
                byteorder="little",
                signed=False
            )
            uint2 = int.from_bytes(
                new_string[(i + 1) * 4:(i + 1) * 4 + 4],
                byteorder="little",
                signed=False
            )

            # Nothing to explain here
            # I just don't really know how it works
            temp = (0x0e79a9c1 * uint1) % 0x7fffffff
            temp = (sha_256_parts[0] * (temp + n_low) + sha_256_parts[1]) % 0x7fffffff
            n_high += temp

            temp = (uint2 + temp) % 0x7fffffff
            n_low = (sha_256_parts[2] * temp + sha_256_parts[3]) % 0x7fffffff
            n_high += n_low

        # XORing initial integers saved earlier with finel n_low and n_high values
        new_hash_parts[0] ^= n_low
        new_hash_parts[1] ^= n_high
        new_hash_parts[2] ^= n_low
        new_hash_parts[3] ^= n_high

        for i in range(4):
            # Adgusting little-endianness
            part = new_hash_parts[i]
            part = (((part & 0xff) << 24) | ((part & 0xff00) << 8) |
                    ((part >> 8) & 0xff00) | ((part >> 24) & 0xff))
            hexpart = hex(part)
            # I don't know if it's the best way to concatenate HEX values
            # TODO: Check if there's a clean way to do this, without .lstrip("0x")
            # Ensuring that the final value is the length of ten
            self.lock_and_key_response += "0" * (8 - len(hexpart.lstrip("0x"))) + hexpart.lstrip("0x")

        # Making a request with generated lockAndKeyResponse value to get registrationToken
        headers = {
            "Connection": "close",
            "BehaviourOverride": "redirectAs404",
            "LockAndKey": "appid={}; time={}; lockAndKeyResponse={}".format(
                self.k_lock_and_key_appid,
                time_value,
                self.lock_and_key_response
            ),
            "ClientInfo": self.k_client_info,
            "Host": self.urls["messages_old?"],
            "Content-Type": "application/json",
            "Authentication": "skypetoken={}".format(self.skypetoken),
        }

        response = self.session.post(url, headers=headers, json={})

        # Parsing a registrationToken from response
        registration_token_raw = response.headers["set-registrationtoken"]
        for line in registration_token_raw.split("; "):
            k, v = line.split("=")
            self.registration_token[k] = v

        return(self.registration_token["registrationToken"])

    def send_message(self, chat, message):
        """
        Sends message to given chat (the chatname shold be unformatted, e.g. "8:[skype_username],"
        or "19:[chathash]@thread.skype", or "1:[live_username]")
        """
        # Creating a path url to which request will be sent
        chat_url = "/v1/users/ME/conversations/{}/messages".format(chat)
        # Creating a full url out of path url and messaging host
        request_url = "https://{}{}".format(self.urls["messages"], chat_url)

        # This is the json for the message to send
        data = {
            # JavaScript generates time in miliseconds, so we have to multiply it by 1000
            "clientmessageid": str(round(time.time() * 1000)),
            # This .replace("<br>", "\r\n") is not really needed, used for messengers like pidgin
            # That use html tags to terminate lines
            "content": message.replace("<br>", "\r\n"),
            "messagetype": "RichText",
            "contenttype": "text",
        }

        headers = {
            "RegistrationToken": "registrationToken={}".format(
                self.registration_token["registrationToken"]
            ),
            "Referer": "https://web.skype.com/en/",
            "Accept": "application/json; ver=1.0;",
            "ClientInfo": self.k_client_info,
            "BehaviorOverride": "redirectAs404",
        }

        if message.startswith("/me"):
            data["skypeemoteoffset"] = "4"

        # Making a request to generated url and trying to send a message
        response = self.session.post(request_url, headers=headers, json=data)

        return(response)
