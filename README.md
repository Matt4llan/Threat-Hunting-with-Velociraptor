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


## Steps

I have already downloaded Ubuntu 20.04 for this lab and opened it up in VMware Workstation and have my Veloceraptor server set up and ready to go

![image](https://github.com/Matt4llan/Threat-Hunting-with-Velociraptor/assets/156334555/c398f222-591a-43da-aa31-9b0e8910757e)

After SSH'ing to the abover server and elevating to root i am inporting some hunts.

```
ssh user@192.168.149.130
sudo su
```

Opening up the web UI to view Veloceraptor 'https://192.168.149.130:8889/app/index.html#/hunts'

