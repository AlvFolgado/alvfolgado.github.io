---
layout: post
title:  "Ruby/Python/JS Command and Argument Injection"
categories: Offensive AppSec 
tags:  CommandInjection
author: Alvaro Folgado (@rebujacker)
---

* content
{:toc}


![](/images/post20171024/intro.jpg)

## Introduction

Following the thread about Command and Argument Injections, with the objective of gathering all these dangerous functions I proceed with three popular scripting languages used to build webapps. In this time I will present three PoC's, but the idea is just the same. Payloads to use alongside the install guide will be inside each PoC file, I will focus in the explanation from a source code point of view. This post could appear repetitive, but I try to help attackers and defenders to understand that I can handle in a similar way our software independently of the technology. As you can see not only the solutions are similar, but also the C source code of each language is similarly implemented.


## Ruby/Rails

This [PoC](https://github.com/rebujacker/WebRCEPoCs/tree/master/ruby/CommandArgI) is built for the ruby scenario using rails framework.

Following the structure from previous PoC's I have the main controller of the PoC:

mails_controller.rb:

```ruby
    def mailpost

        if ((params[:emailFrom] != nil) and (params[:emailTo] != nil) and (params[:body] != nil) and (params[:submit] == 'Command Injection'))

            emailTo = params[:emailTo]
            emailFrom = params[:emailFrom]
            body = params[:body]

            payload = "/usr/sbin/sendmail -f" + emailFrom
            exec("#{payload}")
            #This one is special, we should have control over the entire string, and start with "|" plus commands
            #open("#{payload}")

    [...]
```

Ruby has many functions to call a OS process. Between them let's analyze two:

1."exec('command')" ==> This command accept an string as input and pass it to the sh/bash interpreter. Without escaping I can break it and perform more commands.

Let's look at the Ruby C source code as we did in previous PoCs.

/ruby/process.c:

```c

[...]

rb_define_global_function("exec", rb_f_exec, -1);

[...]

rb_f_exec(int argc, const VALUE *argv)
{
    VALUE execarg_obj, fail_str;
    struct rb_execarg *eargp;
#define CHILD_ERRMSG_BUFLEN 80
    char errmsg[CHILD_ERRMSG_BUFLEN] = { '\0' };
    int err;

    execarg_obj = rb_execarg_new(argc, argv, TRUE);
    eargp = rb_execarg_get(execarg_obj);
    before_exec(); /* stop timer thread before redirects */
    rb_execarg_parent_start(execarg_obj);
    fail_str = eargp->use_shell ? eargp->invoke.sh.shell_script : eargp->invoke.cmd.command_name;

    rb_exec_async_signal_safe(eargp, errmsg, sizeof(errmsg));

[...]

proc_exec_sh(const char *str, VALUE envp_str)
{

[...]

#else
    if (envp_str)
        execle("/bin/sh", "sh", "-c", str, (char *)NULL, (char **)RSTRING_PTR(envp_str)); /* async-signal-safe */
    else
        execl("/bin/sh", "sh", "-c", str, (char *)NULL); /* async-signal-safe (since SUSv4) */
#endif


[...]

```

Following the different methods calls from the "exec" function to the actual "execle" in the ruby C source code you can see a normal OS process call to "/bin/sh -c" is being performed. 

2."open('\|command')" .This one is particularly special. To trigger it I need to use "\|" in from of the classic payload.

/ruby/io.c:
```c

rb_define_global_function("open", rb_f_open, -1);

[...]

rb_f_open(int argc, VALUE *argv)
{
    ID to_open = 0;
    int redirect = FALSE;

    if (argc >= 1) {
    CONST_ID(to_open, "to_open");
    if (rb_respond_to(argv[0], to_open)) {
        redirect = TRUE;
    }
    else {
        VALUE tmp = argv[0];
        FilePathValue(tmp);
        if (NIL_P(tmp)) {
        redirect = TRUE;
        }
        else {
                VALUE cmd = check_pipe_command(tmp);
                if (!NIL_P(cmd)) {
            argv[0] = cmd;
            return rb_io_s_popen(argc, argv, rb_cIO);

[...]

check_pipe_command(VALUE filename_or_command)
{
    char *s = RSTRING_PTR(filename_or_command);
    long l = RSTRING_LEN(filename_or_command);
    char *e = s + l;
    int chlen;

    if (rb_enc_ascget(s, e, &chlen, rb_enc_get(filename_or_command)) == '|') {
        VALUE cmd = rb_str_new(s+chlen, l-chlen);
        OBJ_INFECT(cmd, filename_or_command);
        return cmd;

[...]

```

Where "open" function is normally use to open files, you can see in the source code that by providing a pipe symbol "\|" you are able to call OS processes using the default function popen. This mean that in some situations you will need to try "\|payload" to succeed in som ruby command injection scenarios.


On the other hand for the Argument Injection, I needed to perform some changes in the PoC:

```ruby
    [...]

        elsif ((params[:emailFrom] != nil) and (params[:emailTo] != nil) and (params[:body] != nil) and (params[:submit] == 'Argument Injection'))


            #Even if each element of the payload is escaped to avoid injection of sh elements, the tokenization considers spaces, and we can create extra arguments.
            payload = "/usr/sbin/sendmail -f" + emailFrom
            tokenizedPayload = payload.gsub(/\s+/, ' ').strip.split(" ")
            tokenizedPayload.map {|x| Shellwords.escape(x)}
            print tokenizedPayload
            IO.popen(tokenizedPayload)

    [...]

```

"IO.popen" accepts directly an string that will be passed to a "/bin/sh" or an array of elements which first argument will be the process to fork alongside with input arguments. Using this, I can create an Argument Injection scenario where Command Injection is not more possible (user Input is being escaped), but yes an Argument Injection. In this one, I had manually tokenized the user input to mimetize correctly a possible similar behaviour by some untrusted code (the tokenization of spaces will be key to create new arguments).


## Python/Django

In the python one I will follow the exact same structure.

```python
        if (not(emailTo == "") and not(emailFrom == "") and not(body == "") and (submit == 'Command Injection')):

            payload = "/usr/sbin/sendmail -f" + emailFrom

            #Three ways to invoke commands in Python
            #os.system(payload)
            os.popen(payload)
            #subprocess.call(payload,shell=True)

```

First, the command injection is performed using "os.popen". Exactly in the same way that Ruby "exec", the "os.popen" basically calls a "subprocess.popen" with "Shell=True". This will create automatically a subprocess with a '/bin/sh' as the source cpython code shows:


/cpython/Lib/os.py
```python

def popen(cmd, mode="r", buffering=-1):
    if not isinstance(cmd, str):
        raise TypeError("invalid cmd type (%s, expected string)" % type(cmd))
    if mode not in ("r", "w"):
        raise ValueError("invalid mode %r" % mode)
    if buffering == 0 or buffering is None:
        raise ValueError("popen() does not support unbuffered streams")
    import subprocess, io
    if mode == "r":
        proc = subprocess.Popen(cmd,
                                shell=True,
                                stdout=subprocess.PIPE,
                                bufsize=buffering)
        return _wrap_close(io.TextIOWrapper(proc.stdout), proc)


```


/cpython/Lib/subprocess.py
```python

class Popen(object):

[...]

           self._execute_child(args, executable, preexec_fn, close_fds,
                                pass_fds, cwd, env,
                                startupinfo, creationflags, shell,
                                p2cread, p2cwrite,
                                c2pread, c2pwrite,
                                errread, errwrite,
                                restore_signals, start_new_session)
[...]


def _execute_child(self, args, executable, preexec_fn, close_fds,//...

[...]

            if shell:
                # On Android the default shell is at '/system/bin/sh'.
                unix_shell = ('/system/bin/sh' if
                          hasattr(sys, 'getandroidapilevel') else '/bin/sh')
                args = [unix_shell, "-c"] + args
                if executable:
                    args[0] = executable



[...]

                    self.pid = _posixsubprocess.fork_exec(
                            args, executable_list,
                            close_fds, tuple(sorted(map(int, fds_to_keep))),
                            cwd, env_list,
                            p2cread, p2cwrite, c2pread, c2pwrite,
                            errread, errwrite,
                            errpipe_read, errpipe_write,
                            restore_signals, start_new_session, preexec_fn)
                    self._child_created = True
[...]
```

/cpython/Modules/_posixsubprocess.c
```c

subprocess_fork_exec(PyObject* self, PyObject *args)
{

[...]
    pid = fork();
    if (pid == 0) {

        if (preexec_fn != Py_None) {
            PyOS_AfterFork_Child();
        }

        child_exec(exec_array, argv, envp, cwd,
                   p2cread, p2cwrite, c2pread, c2pwrite,
                   errread, errwrite, errpipe_read, errpipe_write,
                   close_fds, restore_signals, call_setsid,
                   py_fds_to_keep, preexec_fn, preexec_fn_args_tuple);
        _exit(255);
        return NULL;  
    }
[...]

```


Again, for the Argument Injection I follow the same technique escaping every shell special character using "pipes.quote" but I tokenize user input "emailFrom". As "IO.popen" in ruby , python has "subprocess.call" or "subprocess.popen". As you saw in the source code this function let us choose between call directly a '/bin/sh' or just fork a new process of an input array of elements (also,similar to processbuilder in java). Looking at the controller: 



```python

        elif (not(emailTo == "") and not(emailFrom == "") and not(body == "") and (submit == 'Argument Injection')):

            #A classic Argument Injection using "safe" function as subprocess.call with 'shell=False'
            emailFromQuoted = pipes.quote(emailFrom)
            command = "/usr/sbin/sendmail -f" + emailFromQuoted
            payload = command.split()
            subprocess.call(payload,shell=False)


```


Using given payloads in the PoC folder we can see this is working correctly.


## Javascript/NodeJS

Last by not least, let's go with Javascript used in server-side code. NodeJS is the framework used in this PoC, and the controller will look similar that Ruby/Python ones: 

```javascript

    if(submit == 'Command Injection'){

        var payload = "/usr/sbin/sendmail -f" + emailFrom

        //We have other functions inside 'child_process' itself...,other libraries like 'shelljs' ,etc
        exec(payload, function(error, stdout, stderr) {});

    }else if(submit == 'Argument Injection'){

        //Tokenization of user input happens and Argument Injection could happen
        var tokenizedPayload = emailFrom.split(" ");
        var tokenizedPayload2 = tokenizedPayload.splice(0,0,"-f");

        var child = spawn('/usr/sbin/sendmail', tokenizedPayload);

```


Almost every function used to perform process calls come from NodeJS library "child_process". I will use "exec" and "spawn" for the Argument Injection. In this time, the source code to look into will be the one from NodeJS (since is where almost all the server-side porperties of javascript are being implemented).


/node/deps/npm/lib/utils/spawn.js
```javascript

function spawn (cmd, args, options) {
  var cmdWillOutput = willCmdOutput(options && options.stdio)

  if (cmdWillOutput) npwr.startRunning()
  var raw = _spawn(cmd, args, options)
  var cooked = new EventEmitter()

[...]


```

/node/deps/uv/src/unix/process.c
```c

int uv_spawn(uv_loop_t* loop,
             uv_process_t* process,
             const uv_process_options_t* options) {

[...]

pid = fork();

  if (pid == -1) {
    err = -errno;
    uv_rwlock_wrunlock(&loop->cloexec_lock);
    uv__close(signal_pipe[0]);
    uv__close(signal_pipe[1]);
    goto error;
  }

[...]
```


## Conclusions

As an **Attacker**, finding those vulnerabilities from a black blox perspective can be really easy to spot or really difficult. As said in previous post, debugging messages could help us, for that we can apply clever fuzing in functions/features we know could be using some OS processes. From a offensive research point of view, this could be really useful if we know target technology and we are able to spot new vulnerabilities in some 3PP libraries that are being used.


As a **Defender**, if you really need to use OS commands with user inputs,remember using safe functions to craft your calls (extra escaping formating to be strick with these inputs is always a good idea). Keep updated all 3PP's and look for published 0day's in the wild, post part of big web owning nowadays come from outdated used 3PP.

## References

Particular thanks to internet and stack overflow for helping me to create these PoC's in so many different techs.

