# skypy
A python library which allows you to send messages via web.skype.com

At this moment the only features it provides are authentication and sending messages.

More on the way

## Installation
Since this library is a single file and currently in the development there's no way to install it aside from downloading the file and importing library.

## Usage

Example:
```
from skypy import Skype
client = Skype("username", "password")
client.authenticate()
client.get_registration_token()
client.send_message("8:some_user", "Hello, world")
```

Currently supported features are  authentication and messaging. There is no way to list contacts and chats yet, though i'm working on it.

The only way right now to get a username (or a chatname, for that matter) is to go to the web.skype.com, authorize and look for urls used to send messages in the browser debug tool, some of them will look like:

`https://client-s.gateway.messenger.live.com/v1/users/ME/conversations/{CHATNAME/USERNAME}/messages`


You only need the part between "/conversations/" and "/messages"

So if the url looks like `https://client-s.gateway.messenger.live.com/v1/users/ME/conversations/8:foobar/messages`

your chatname will be `8:foobar`
## Thanks
Eion Robb for his skypeweb pidgin plugin (https://github.com/EionRobb/skype4pidgin), which serves me as a reference

## Legal
Skype is the trademark of Skype Limited
