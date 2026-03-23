# Pokebot - Cybersecurity Recon Helper
**Pokebot** speeds up pentesting for your clients or yourself. It's a Python-powered, GPT-powered agent that performs basic initial recon tools on your behalf.
Currently **only Linux** is supported.

# Use & Install
```
git clone https://github.com/mdunn99/poke-bot.git
cd poke-bot
```

## Install Python Dependencies
`pip install -r requirements.txt`

## Install searchsploit If Necessary
```
sudo apt install git
git clone --depth 1 https://gitlab.com/exploit-database/exploitdb.git /opt/exploit-database # Clone the repo
sudo ln -sf /opt/exploit-database/searchsploit /usr/local/bin/searchsploit # Add searchsploit to your PATH
```

## Set Your API Key
`echo '<YOURAPI_KEY_HERE>' > .env`

# Features
- Structured prompt parsing (good for security: don't give an agent a shell!)
- Uses SecLists for wordlists

## Tools
- Nmap
- ffuf
- exploitdb search

