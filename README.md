# Threat Hunting with Velociraptor - Long Tail Analysis Lab

## Objective

In this lab, we will import previously run hunts across 10 similar systems, using stacking/grouping to identify outliers. 

## Skills Learned
- Run a Kerberoasting attack

## Tools Used
- Ubuntu 20.04
- SSH
- Windows CLI
- VMware Workstation


## Step 1 - Setup

I have already downloaded Ubuntu 20.04 for this lab and opened it up in VMware Workstation and have my Veloceraptor server set up and ready to go

![image](https://github.com/Matt4llan/Threat-Hunting-with-Velociraptor/assets/156334555/c398f222-591a-43da-aa31-9b0e8910757e)

After SSH'ing to the abover server and elevating to root i am inporting some hunts.

```
ssh user@192.168.149.130
sudo su
```

Opening up the web UI to view Veloceraptor 'https://192.168.149.130:8889/app/index.html#/hunts'

![image](https://github.com/Matt4llan/Threat-Hunting-with-Velociraptor/assets/156334555/0ef9545f-daca-44be-9782-32a1229227dc)


## Step 2 - Let's Dive Into The Hunts

Firstly i have been provided with a guide on Velociraptor Notebooks: 'https://detailed-leo-854.notion.site/Velociraptor-Notebook-Tips-c9afcf3aec3945668aeaf1ed6cab7324'

For this lab i have selected the the Hunt 'Stacking - Windows.System.Plist' and will be using the provided notebook to check for untrusted processes.

```
SELECT Name,Exe,CommandLine,Hash.SHA256 AS SHA256, Authenticode.Trusted, Username, Fqdn FROM source()
WHERE Authenticode.Trusted = "untrusted"
```

At this point the lab tells us that we should be asking the basic question "How common are untrusted processes across these systems?"

Lets find out using the provided notebook.

![image](https://github.com/Matt4llan/Threat-Hunting-with-Velociraptor/assets/156334555/d092d9bc-99e6-4765-bdf1-89abea40f53b)

1 result

Next Question - "What are the rarest combinations of process executables and their command line arguments?"

I will use the provided notbook

```
SELECT Name,Exe,CommandLine,Hash.SHA256 AS SHA256, Authenticode.Trusted, Username, Fqdn, count() AS Count FROM source()
// Stack for prevalence of Exe path + CommandLine arguments
GROUP BY Exe,CommandLine
// Sort results ascending, showing rarest first
ORDER BY Count
```

Here i need to filter through the results and find what i think to be unusual. Here i need to modify the notebook and this is where the guide came in handy as i need to filter out some of what i think is normal. Below is the notebook i ended up with to try and filter out the noise.

```
SELECT Name,Exe,CommandLine,Hash.SHA256 AS SHA256, Authenticode.Trusted, Username, Fqdn, count() AS Count FROM source()
WHERE NOT CommandLine =~ "svchost\.exe.-k"
AND NOT Exe =~ "(sppsvc|Discord|backgroundTaskHost|MicrosoftEdgeUpdate|(System|Windows)Apps|Adobe|CCleaner|HMA VPN)"
// Stack for prevalence of Exe path + CommandLine arguments
GROUP BY Exe,CommandLine
// Sort results ascending, showing rarest first
ORDER BY Count
```

Hints were given e.g "we can often exclude executions of svchost.exe when it is accompanied with a -k command line argument as this will create many “false positives” of appearing to be unique across systems when it facts it likely the same services being run but with slightly different names"

After this we were mostly left with 'C:\Windows\System32\rundll32.exe' and other commandline executions. I guess this is where experience tells you that you are onto something! this is experience i am yet to gain. 

The answer was the rundll32 commands:
One of the executions of rundll32.exe has no command line argument. Typically we’d expect to see a DLL path in the CLI args for rundll32.exe and this path should typically be a well-known location for DLLs.
The other rundll32.exe points to a DLL in a \\Temp\\ folder which is unusual. We’d need to dig deeper to know for sure if this is legitimate.

![image](https://github.com/Matt4llan/Threat-Hunting-with-Velociraptor/assets/156334555/8e69ed28-1a00-40b3-ac7c-6fc7648062a0)

## Baselining Network Activity

I like the way this lab is set out making me ask questions along the way to get my head into the mind of a SOC Analyst... 

### Question - What are the most/least common network connections across these systems?

Lets open up the Hunt - 'Stacking - Windows.Network.Netstat' and use the supplied Notebook which will group and count all network connections by process Name and Raddr.IP or “remote address IP.”

```
SELECT Name,Family,Type,Status,`Laddr.IP`,`Laddr.Port`,`Raddr.IP`,`Raddr.Port`,Fqdn, count() AS Count FROM source(artifact="Windows.Network.Netstat")
GROUP BY Name,`Raddr.IP`
ORDER BY Count
```

![image](https://github.com/Matt4llan/Threat-Hunting-with-Velociraptor/assets/156334555/43c384af-01d0-4854-a6a7-c1f1ad1482a1)

So what are we actually looking at here? We are seeing what these systems were doing over the network at the time of the hunt.

We need to specifically look for:
  Traffic over unusual ports
  Outbound traffic by unusual processes, or processes that don’t regularly make internet connections
  Traffic between workstations
  Connections to suspicious IP addresses (requires OSINT enrichment)

So again we need to play with the notebook to filter out the noise and concentrate on more interesting connections
  
Below is the Notebook i ended up with to filter out entries that had no remote address

```
SELECT Name,Family,Type,Status,`Laddr.IP`,`Laddr.Port`,`Raddr.IP`,`Raddr.Port`,Fqdn, count() AS Count FROM source(artifact="Windows.Network.Netstat")
WHERE NOT `Raddr.Port` =~ "0"
AND NOT `Raddr.IP` =~ "(0\.0\.0\.0|::)"
GROUP BY Name,`Raddr.IP`
ORDER BY Count
```

Now we can easily see the same rundll32.exe going out to a remote IP 70.34.248.30 over port 443 which is HTTPS

![image](https://github.com/Matt4llan/Threat-Hunting-with-Velociraptor/assets/156334555/244abae3-0297-4a3a-8198-35e8cd5a648c)

If i pop that IP into google it shows up on a few blocklists possibly associated with Malware.

![image](https://github.com/Matt4llan/Threat-Hunting-with-Velociraptor/assets/156334555/41417b61-645a-4c46-9684-c4862c32313b)







