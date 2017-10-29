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


## PHP  

### Command/Argument Injection

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

//The mail PHP is prone to Argument Injection by default 
mail($emailTo,$subject,$body,$headers,$InjectableExtraParams);
```

## JAVA

### Command Injection:

```java

//We are passing strings without control to a sh/bash/cmd ==> Command Injection

String[] cmd = new String[]{"/bin/bash","-c","/usr/sbin/sendmail -f"+emailFrom};

Runtime.getRuntime().exec(cmd);

ProcessBuilder pb = new ProcessBuilder(cmd);
pb.start();

```

### Argument Injection:

```java
//We are invoking an process without calling a sh/bash/cmd . But Still, thanks to Runtime.java tokenizer, we are able to inject extra arguments to target process.

String cmd = "/usr/sbin/sendmail -f" + emailFrom;
Runtime.getRuntime().exec(cmd);
```


## RUBY

### Command/Argument Injection


```ruby
#Kernel Module
system("#{payload}")

#Finish the server
exec("#{payload}")

#Doesn't leave trace in server log?
`#{payload}`
%x( #{payload} )
%x{ #{payload} }
%x[ #{payload} ]
%x< #{payload} >
			
#This one is special, we should have control over the entire string, and start with "|" plus commands
open("#{payload}")

#Process Module
spawn("#{payload}")

#IO Module, accepts and array with process to build and arguments as well
IO.popen("#{payload}")
```

## PYTHON

### Command/Argument Injection


```python

#Three ways to invoke commands in Python
os.system(payload)
os.popen(payload)
subprocess.call(payload,shell=True)

#No more possible to break /bin/sh but still able to inject new arguments to target process 
subprocess.call(payload,shell=False)

```

## JS

### Command/Argument Injection

```javascript
//Basically everything comming from NodeJS "child_process" should be watched
exec(payload, function(error, stdout, stderr) {});

//Argument Injection example
var child = spawn('/usr/sbin/sendmail', ['-f', emailFrom]);
```



## Comments

{% include comments.html %}
