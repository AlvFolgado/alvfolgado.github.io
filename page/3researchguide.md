---
layout: page
title: Research-Guide
permalink: /researchguide/
icon: bookmark
type: page
---

* content
{:toc}

In this section I will provide the list of dangerous functions from the different languages and techniques that we could use to find out more bugs in 3PP libraries.


## PHP - Command/Argument Injection:

```php
//Popen call pipe to the target process, is totally Command Injectable
popen("/usr/sbin/sendmail -f".$emailFrom,"r");

//Same as Popen!
shell_exec("/usr/sbin/sendmail -f".$emailFrom);

//Same as Popen!
passthru("/usr/sbin/sendmail -f".$emailFrom);

//Same as Popen!
exec("/usr/sbin/sendmail -f".$emailFrom);

//Same as Popen!
system("/usr/sbin/sendmail -f".$emailFrom);

//Same as popen! Litle more conf params, but can happen.
$descriptorspec = array(
   0 => array("pipe", "r"),  // stdin is a pipe that the child will read from
   1 => array("pipe", "w"),  // stdout is a pipe that the child will write to
   2 => array("file", "/tmp/error-output.txt", "a") // stderr is a file to write to
);
$cwd = '/tmp';
$env = array('some_option' => 'aeiou');
proc_open("/usr/sbin/sendmail -f".$emailFrom, $descriptorspec, $pipes, $cwd, $env);

//Same as popen. Funny backticks lol
`/usr/sbin/sendmail -f{$emailto}`;

//Actually only working in CGI and PHP-CLI directly
pcntl_exec("/usr/sbin/sendmail -f".$emailFrom);
```

## PHP - Argument Injection:

```php
mail($emailTo,$subject,$body,$headers,$InjectableExtraParams);
```
## Comments

{% include comments.html %}
