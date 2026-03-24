# Pokebot - Cybersecurity Recon Helper
**Pokebot** speeds up pentesting for your clients or yourself. It's a GPT-powered agent that performs basic initial recon tools on your behalf.
Currently **only Linux** is supported.

# Use & Install
```
git clone https://github.com/mdunn99/poke-bot.git
cd poke-bot
```

## Install Python Dependencies
`pip install -r requirements.txt`

## Install Other Dependencies:
Nmap: https://github.com/nmap/nmap
Searchsploit: https://gitlab.com/exploit-database/exploitdb.git
ffuf: https://github.com/ffuf/ffuf

## Set Your API Key
`echo 'OPEN_API_KEY=<YOURAPI_KEY_HERE>' > .env`

# Features
- Structured prompt parsing (good for security: don't give an agent a shell!)
- Uses SecLists for wordlists

## Tools
- Nmap
- ffuf
- exploitdb search

# Working On
Implementing httpx to allow agent to intercept requests and responses at the transport layer.