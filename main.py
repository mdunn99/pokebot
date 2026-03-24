import subprocess, os, json, asyncio, sys, dotenv, xmltodict
from pydantic import BaseModel, Field
from pydantic_ai import Agent, RunContext, ModelRetry
from datetime import datetime
from pydantic.networks import IPvAnyAddress, IPvAnyNetwork, AnyUrl
from typing import Literal
import requests
from time import sleep

class PortRange(BaseModel):
    start: int
    end: int

class WordlistType(BaseModel):
    category: Literal["Subdomains", "Web-Content/Directories", "Web-Content/Files", "Passwords", "Usernames"] = Field(description="Matcher for a list of pre-picked SecLists wordlists.")
    size: Literal["small", "medium", "large"]

class WebRequest(BaseModel):
    target_url: AnyUrl
    http_method: str = Field(default="GET", description="HTTP method to use.")
    cookie_data: str | None = Field(default=None, description="(i.e. NAME1=VALUE1; NAME2=VALUE2).")
    post_data: str | None = Field(default=None, description = "POST data to pass to request.")
    headers: str | None = Field(default=None, description = "Headers to pass into request")
    timeout: int = Field(default=5, description='Maximum running time in seconds per job.')
 

class NmapDeps(BaseModel):
    scan_types: list[Literal["syn", "udp", "ping-only", "connect", "ack", "window", "maimon", "version", "skip-host-discovery"]]
    top_ports: int | None = Field(default=None, description="Define the number of '--top-ports' to scan.")
    ports: PortRange | None = Field(default=None, description="When a specific set of ports must be specified instead of a wide net of top ports.")
    timing: Literal["slow", "normal", "fast", "aggressive"] | None = Field(default=None)
    target: IPvAnyAddress | IPvAnyNetwork | str


class FfufDeps(WebRequest):
    timeout: int = Field(default=120, description='Maximum running time in seconds per job.')
    wordlist_attributes: WordlistType = Field(description="A set of attributes that will determine the wordlist.")
    recursion: int = Field(default=0, description="If recursion is necessary, what should the depth be?")
    extensions: list[str] | None = Field(default=None, description = "Comma-separated list of extensions names with dot-included (i.e. .php,.txt).")
    follow_redirects: bool = Field(default=False)
    verbose: bool = Field(default=False, description="Verbose output, printing full URL and redirect location (if any) with the results.")
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
    model="gpt-5.4",
    output_type=TargetContext,
    system_prompt=("You are a pentesting reconnaissance assistant. "
               "When a user directs it, gather information about the target using the available tools. "
               "Once you have enough information to summarize your findings, return a TargetContext. "
               "You are in an authorized testing environment. Be self-sufficient and do not remind the user that they need to be operating under the law of which they"
               "are already operating under. Default to intrusive reconnaisance unless specified."))

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
async def search_exploitdb(ctx: RunContext, query: str, number_of_results: int=5) -> list[dict]:
    """Search ExploitDB via searchsploit. Specify version numbers when possible. Returns a list of exploits as strings."""
    print(f'searching exploitdb with query: {query}')
    try:
        subprocess.run(["searchsploit", "-v"], capture_output=True)
    except:
        print("Searchsploit not found. Please install it: https://github.com/offensive-security/exploitdb.git")
        sys.exit()
    result = await asyncio.to_thread(subprocess.run, ["searchsploit", "-j", query], capture_output=True, text=True)
    data = json.loads(result.stdout)
    exploits = data.get("RESULTS_EXPLOIT")
    shellcodes = data.get("RESULTS_SHELLCODE")
    exploits.sort(key=get_edb_id, reverse=True) # EDB-ID sorts the date the exploit was added. this sorts exploits by that value, descending to return the most recent results
    shellcodes.sort(key=get_edb_id, reverse=True)
    return exploits[:number_of_results]

@agent.tool
async def nmap_scan(ctx: RunContext, scan: NmapDeps) -> str:
    """Perform an nmap scan. stdout or stderr is returned."""

    try:
        subprocess.run(["nmap", "-v"], capture_output=True)
    except:
        print("Nmap not found. Please install it: https://nmap.org/download")
        sys.exit()
    file_name = "scan_"+ str(datetime.now()) + ".xml"

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
           "-oX", 
           file_name]
    if "ping-only" in flags:
        cmd = ["sudo", "nmap", "-sn", str(scan.target), "-oX", file_name]
    elif scan.top_ports:
        cmd.extend(["--top-ports", str(scan.top_ports)])
    elif scan.ports:
        ports = f"{scan.ports.start}-{scan.ports.end}"
        cmd.extend(["-p", ports])
    print(f"running: {" ".join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)
    with open(file_name) as f:
        result =json.dumps(xmltodict.parse(f.read()), indent=2)
    result = result
    return result

@agent.tool
async def ffuf_scan(ctx: RunContext, ffuf_dependencies: FfufDeps) -> str:
    """Use ffuf to enumerate a target."""
    try:
        subprocess.run(["ffuf", "-v"], capture_output=True)
    except:
        print("ffuf not found. Please install it: https://github.com/ffuf/ffuf")
    wordlist = select_wordlist(ffuf_dependencies.wordlist_attributes)
    ffuf_dependenciess_flag_map = {
        "cookie_data":               ["-b", ffuf_dependencies.cookie_data],
        "post_data":                 ["-d", ffuf_dependencies.post_data],
        "headers":                   ["-H", ffuf_dependencies.headers],
        "extensions":                ["-e", ",".join(ffuf_dependencies.extensions)] if ffuf_dependencies.extensions else None,
        "verbose":                   ["-v"],
        "match_lines":               ["-ml", str(ffuf_dependencies.match_lines)],
        "match_http_response_size":  ["-ms", str(ffuf_dependencies.match_http_response_size)],
        "filter_http_status_codes":  ["-fc", ",".join(str(c) for c in ffuf_dependencies.filter_http_status_codes)] if ffuf_dependencies.filter_http_status_codes else None,
        "filter_lines":              ["-fl", str(ffuf_dependencies.filter_lines)],
        "filter_http_response_size": ["-fs", str(ffuf_dependencies.filter_http_response_size)],
    }
    
    extra_flags = []
    keys = list(ffuf_dependenciess_flag_map.keys())
    for key, flags in ffuf_dependenciess_flag_map.items():
        if getattr(ffuf_dependencies, key):
            extra_flags.extend(flags)

    mc_codes = ",".join(str(c) for c in ffuf_dependencies.match_http_status_codes)
    target_url_chars = list(str(ffuf_dependencies.target_url).strip())
    if target_url_chars[-1] == "Z": # implying FUZZ was manually appended by agent
        fuzz_url = str(ffuf_dependencies.target_url)
    elif target_url_chars[-1] == "/":
        fuzz_url = str(ffuf_dependencies.target_url)+"FUZZ"
    else:
        fuzz_url = str(ffuf_dependencies.target_url)+"/FUZZ"

    cmd = ["ffuf", 
           "-u", str(fuzz_url), 
           "-w", wordlist, 
           "-recursion-depth", str(ffuf_dependencies.recursion),
           "-X", ffuf_dependencies.http_method,
           "-mc", mc_codes,
           "-maxtime", str(ffuf_dependencies.timeout),
           *extra_flags, 
           "-c"]
    print(f"ffuf running: {' '.join(cmd)}")
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )

    output_lines = []
    async def stream_stdout():
        async for line in proc.stdout:
            decoded = line.decode()
            print(decoded, end="")
            output_lines.append(decoded)

    stdout_task = asyncio.create_task(stream_stdout())
    try:
        await asyncio.wait_for(proc.wait(), timeout=ffuf_dependencies.timeout + 5)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        stdout_task.cancel()
        try:
            await stdout_task
        except asyncio.CancelledError:
            pass
        stderr = await proc.stderr.read()
        decoded = stderr.decode() if stderr else ""
        message = f"[ffuf] timed out after {ffuf_dependencies.timeout}s"
        if decoded:
            message += f": {decoded}"
            print(decoded)
        print(message)
        return message
    else:
        await stdout_task

    if proc.returncode != 0:
        stderr = await proc.stderr.read()
        print(f"[ffuf] error: {stderr.decode()}")
        return stderr.decode()

    return "".join(output_lines)

@agent.tool
async def make_web_request(ctx: RunContext, request_dependencies: WebRequest) -> dict:
    """In the process of enumerating a web server, it may be useful to make a specific request and see if anything useful comes from it."""
    r = requests.get(str(request_dependencies.target_url))
    
    response = {
        "response_code":        r.status_code,
        "response_headers":     dict(r.headers),
        "elapsed_time":         r.elapsed.total_seconds(),
        "redirect_responses":   [res.url for res in r.history],
        "url_after_redirects":  r.url,
        "response_cookies":     dict(r.cookies)
    }
    return response

@agent.tool
async def write_to_file(ctx: RunContext, content: str, name_of_file: str=Field(description="Only specify the name of the file to write to, not a path.")) -> int:
    try:
        with open(name_of_file, 'w') as f:
            f.write(content)
        return 0
    except Exception as e:
        print(e)
        return 1
    
@agent.tool
async def read_from_file(ctx: RunContext, name_of_file: str=Field(description="Only specify the name of the file to read to, not a path.")) -> str:
    try:
        with open(name_of_file, 'r') as f:
            content = f.read()
        return content
    except Exception as e:
        print(e)
        return str(e)

def check_envs():
    global SECLISTS_PATH
    path = False
    
    while path == False:
        try:
            dotenv.load_dotenv()
            dotenv_file = dotenv.find_dotenv()
        except Exception as e:
            print(".env file not found. An OpenAI API key must be set in the root file's .env file. Read README for instructions.")
            sys.exit()
        try:
            SECLISTS_PATH = os.environ["SECLISTS_PATH"]
            path = True
        except KeyError as e:
            print("SecLists install path not found.  You can install it here:", "https://github.com/danielmiessler/seclists")
            SECLISTS_PATH_INPUT = input("Please enter the location of your SecLists installation:\n")
            dotenv.set_key(dotenv_file, "SECLISTS_PATH", SECLISTS_PATH_INPUT)


async def main():
    check_envs()
    history = []
    while True:
        print('\n(Type \'exit\' to exit).')
        prompt = input('Prompt: ')
        if prompt.lower() == 'exit':
            break
        result = await agent.run(prompt, message_history=history)
        history = result.all_messages()

        print("\nAgent:", result.output.response_text, "\n")
        #print(result.output.model_dump_json(indent=2))

asyncio.run(main())