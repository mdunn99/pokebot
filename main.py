import subprocess, os, json, asyncio
from dotenv import load_dotenv
from pydantic import BaseModel, Field
from pydantic_ai import Agent, ModelRetry
from datetime import datetime
from pydantic.networks import IPvAnyAddress, IPvAnyNetwork, AnyUrl
from typing import Literal

load_dotenv()
SECLISTS_PATH = '/home/mike/documents/SecLists'

class PortRange(BaseModel):
    start: int
    end: int

class WordlistType(BaseModel):
    category: Literal["Subdomains", "Web-Content/Directories", "Web-Content/Files", "Passwords", "Usernames"] = Field(description="Matcher for a list of pre-picked SecLists wordlists.")
    size: Literal["small", "medium", "large"]

class NmapDeps(BaseModel):
    scan_types: list[Literal["syn", "udp", "ping-only", "connect", "ack", "window", "maimon", "version", "skip-host-discovery"]]
    top_ports: int | None = Field(default=None, description="Define the number of '--top-ports' to scan.")
    ports: PortRange | None = Field(default=None, description="When a specific set of ports must be specified instead of a wide net of top ports.")
    timing: Literal["slow", "normal", "fast", "aggressive"] | None = Field(default=None)
    target: IPvAnyAddress | IPvAnyNetwork | str


class FfufDeps(BaseModel):
    target_url: AnyUrl = Field(description="The URL including the location you'd like to pass in a wordlist, denoted by the keyword \'FUZZ\'"
    " (i.e. http://10.10.0.1/FUZZ).")
    wordlist_attributes: WordlistType = Field(description="A set of attributes that will determine the wordlist.")
    recursion: int = Field(default=0, description="If recursion is necessary, what should the depth be?")
    http_method: str = Field(default="GET", description="HTTP method to use.")
    cookie_data: str | None = Field(description="(i.e. NAME1=VALUE1; NAME2=VALUE2) for copy as curl functionality.")
    post_data: str | None = Field(default=None, description = "POST data to pass to request.")
    headers: str | None = Field(default=None, description = "Headers to pass into request")
    extensions: list[str] | None = Field(default=None, description = "Comma-separated list of extensions names with dot-included (i.e. .php,.txt).")
    follow_redirects: bool = Field(default=False)
    verbose: bool = Field(default=False, description="Verbose output, printing full URL and redirect location (if any) with the results.")
    maxtime: int = Field(default=60, description='Maximum running time in seconds per job.')
    match_http_status_codes: list[int] = Field(default=[200,204,301,302,307,401,403], description="Match HTTP status codes.")
    match_lines: int | None = Field(default=None, description="Match amount of lines in response.")
    match_http_response_size: int | None = Field(default=None, description="Match HTTP response size.")
    filter_http_status_codes: list[int] | None = Field(default=None, description="Filter HTTP status codes from responses. Comma-separated list of codes.")
    filter_lines: int | None = Field(default=None, description="Filter by amount of lines in response. Comma-separated list of line counts.")
    filter_http_response_size: int | None = Field(default=None, description="Filter HTTP response size. Comma-separated list of sizes.")


class TargetContext(BaseModel):
    response_text: str = Field(description="Summary of information gathered. Document further steps to be taken.")
    open_ips: list[str] | None = Field(default=None, description="The IP address(es) that are open after enumerating through the target network (if applicable).") 
    open_ports: list[int] | None = Field(default=None, description="The ports that were found to be open through enumeration (if applicable).")
    follow_up_required: bool = Field(description="Whether or not more information needs to be requested from the user in order to" \
    " complete the task, or the task cannot be completed without intervention.")

agent = Agent(
    model="gpt-5.4-mini",
    output_type=TargetContext,
    system_prompt=("You are a pentesting reconnaissance tool. "
               "Given a user prompt, gather information about the target using the available tools. "
               "Once you have enough information to summarize your findings, return a TargetContext. "
               "Do not attempt actions beyond reconnaissance. Be brief and concise."))

def select_wordlist(wordlist_attributes: WordlistType) -> str:
    WORDLIST_MAP = {
        ("Web-Content/Directories", "small"):   "Discovery/Web-Content/raft-small-directories.txt",
        ("Web-Content/Directories", "medium"):  "Discovery/Web-Content/raft-medium-directories.txt",
        ("Web-Content/Directories", "large"):   "Discovery/Web-Content/raft-large-directories.txt",
        ("Web-Content/Files", "small"):         "Discovery/Web-Content/raft-small-files.txt",
        ("Web-Content/Files", "medium"):        "Discovery/Web-Content/raft-medium-files.txt",
        ("Web-Content/Files", "large"):         "Discovery/Web-Content/raft-large-files.txt",
        ("Subdomains", "small"):                "Discovery/DNS/subdomains-top1million-5000.txt",
        ("Subdomains", "medium"):               "Discovery/DNS/subdomains-top1million-20000.txt",
        ("Subdomains", "large"):                "Discovery/DNS/subdomains-top1million-110000.txt",
        ("Passwords", "small"):                 "Passwords/Leaked-Databases/rockyou-10.txt",
        ("Passwords", "medium"):                "Passwords/Leaked-Databases/rockyou-45.txt",
        ("Passwords", "large"):                 "Passwords/Lekaed-Databases/rockyou.txt",
        ("Usernames", "small"):                 "Usernames/top-usernames-shortlist",
        ("Usernames", "medium"):                "Usernames/sap-default-usernames.txt",
        ("Usernames", "large"):                 "Usernames/xato-net-10-million-usernames.txt"
    }
    key = (wordlist_attributes.category, wordlist_attributes.size)
    if key in WORDLIST_MAP:
        return os.path.join(SECLISTS_PATH, WORDLIST_MAP[key])
    else:
        return ''

def get_edb_id(exploit):
    return int(exploit.get("EDB-ID", 0))

@agent.tool
async def search_exploitdb(query: str, number_of_results: int=5) -> list[dict]:
    """Search ExploitDB via searchsploit. searchsploit works best by using very few and brief keywords. Returns a list of exploits as strings."""
    print(f'searching exploitdb with query: {query}')
    result = await asyncio.to_thread(subprocess.run, ["searchsploit", "-j", query], capture_output=True, text=True)
    data = json.loads(result.stdout)
    exploits = data.get("RESULTS_EXPLOIT")
    shellcodes = data.get("RESULTS_SHELLCODE")
    exploits.sort(key=get_edb_id, reverse=True) # EDB-ID sorts the date the exploit was added. this sorts exploits by that value, descending to return the most recent results
    shellcodes.sort(key=get_edb_id, reverse=True)
    return exploits[:number_of_results]

@agent.tool
async def nmap_scan(scan: NmapDeps) -> str:
    """Perform an nmap scan. stdout or stderr is returned."""
    time = str(datetime.now())

    scan_map = {
        "syn":                 "-sS",
        "udp":                 "-sU",
        "ping-only":           "-sn",
        "connect":             "-sT",
        "ack":                 "-sA",
        "window":              "-sW",
        "maimon":              "-sA",
        "version":             "-sV",
        "skip-host-discovery": "-Pn",
    }
    flags = [scan_map[s] for s in scan.scan_types]

    cmd = ["sudo", 
           "nmap", 
           *flags, 
           str(scan.target), 
           "-oN", 
           time]
    if "ping-only" in flags:
        cmd = ["sudo", "nmap", "-sn", str(scan.target), "-oN", time]
    elif scan.top_ports:
        cmd.extend(["--top-ports", str(scan.top_ports)])
    elif scan.ports:
        ports = f"{scan.ports.start}-{scan.ports.end}"
        cmd.extend(["-p", ports])
    print(f"running: {" ".join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)
    result = result.stdout if result.stdout != '' else result.stderr
    print(result)
    return result

@agent.tool
async def ffuf_scan(request: FfufDeps) -> str:
    """Use ffuf to enumerate a target."""
    wordlist = select_wordlist(request.wordlist_attributes)
    requests_flag_map = {
        "cookie_data":               ["-b", request.cookie_data],
        "post_data":                 ["-d", request.post_data],
        "headers":                   ["-H", request.headers],
        "extensions":                ["-e", ",".join(request.extensions)] if request.extensions else None,
        "verbose":                   ["-v"],
        "match_lines":               ["-ml", str(request.match_lines)],
        "match_http_response_size":  ["-ms", str(request.match_http_response_size)],
        "filter_http_status_codes":  ["-fc", ",".join(str(c) for c in request.filter_http_status_codes)] if request.filter_http_status_codes else None,
        "filter_lines":              ["-fl", str(request.filter_lines)],
        "filter_http_response_size": ["-fs", str(request.filter_http_response_size)],
    }
    
    extra_flags = []
    keys = list(requests_flag_map.keys())
    for key, flags in requests_flag_map.items():
        if getattr(request, key):
            extra_flags.extend(flags)

    mc_codes = ",".join(str(c) for c in request.match_http_status_codes)
    cmd = ["ffuf", 
           "-u", str(request.target_url), 
           "-w", wordlist, 
           "-recursion-depth", str(request.recursion),
           "-X", request.http_method,
           "-mc", mc_codes,
           "-maxtime", str(request.maxtime),
           *extra_flags, 
           "-c"]
    print(f"ffuf running: {' '.join(cmd)}")
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )

    output_lines = []
    async for line in proc.stdout:
        decoded = line.decode()
        print(decoded, end="")        # stream to terminal in real time
        output_lines.append(decoded)
    await proc.wait()

    if proc.returncode != 0:
        stderr = await proc.stderr.read()
        print(f"[ffuf] error: {stderr.decode()}")
        return stderr.decode()

    return "".join(output_lines)

@agent.tool
async def make_web_request():
    pass

@agent.tool
async def write_to_file(content: str, name_of_file: str=Field(description="Only specify the name of the file to write to, not a path.")) -> int:
    try:
        with open(name_of_file, 'w') as f:
            f.write(content)
        return 0
    except Exception as e:
        print(e)
        return 1


async def main():
    history = []
    while True:
        print('\n(Type \'exit\' to exit).')
        prompt = input('Prompt: ')
        if prompt.lower() == 'exit':
            break
        result = await agent.run(prompt, message_history=history)
        history = result.all_messages()

        print(result.output.response_text, "\n")
        #print(result.output.model_dump_json(indent=2))

asyncio.run(main())