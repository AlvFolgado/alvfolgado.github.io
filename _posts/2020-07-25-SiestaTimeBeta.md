---
layout: post
title:  "Siesta Time Framework"
categories: RedTeam 
tags:  Implant C2
author: AlvaroFolgado
---

* content
{:toc}


![](https://github.com/rebujacker/SiestaTime/blob/master/src/client/electronGUI/static/icons/png/STicon.png)

## Introduction

Red Team operations require substantial efforts to both create implants and a resilient C2 infrastructure. SiestaTime aims to merge these ideas into a tool with an easy-to-use GUI, which facilitates implant and infrastructure automation alongside its actors reporting. SiestaTime allows operators to provide registrar, SaaS and VPS credentials in order to deploy a resilient and ready to use Red Team infrastructure. The generated implants will blend-in as legitimate traffic by communicating to the infrastructure using SaaS channels and/or common network methods.

Use your VPS/Domains battery to deploy staging servers and inject your favorite shellcode for interactive sessions, clone sites and hide your implants ready to be downloaded, deploy more redirectors if needed. All these jobs/interactions will be saved and reported to help the team members with the documentation process.

SiestaTime is built entirely in Golang, with the ability to generate Implants for multiple platforms, interact with different OS resources, and perform efficient C2 communications. Terraform used to deploy/destroy different Infrastructure.

Beta 1.0 [here](https://github.com/rebujacker/SiestaTime)

## User Guide

Finf the user Guide [here](https://siestatime.readthedocs.io/en/latest/)

## Available Features

**Current Modules/Abilities**

Hive:
    - VPS 
        - AWS
    - Domain
        - GO Daddy
    - SaaS
        - Gmail API

Stagings:
    - Droplet
    - Reverse SSH
    - MSF Handler: HTTPS Let's Encrypt
    - Empire Handler: HTTPS Let's Encrypt

Reporting:
    - Basic Reports

Bichito:

- Network Egression:
    - HTTPS Paranoid GO
    - Self-Signed HTTPS GO
    - Gmail API
    - Gmail API - Mimic TLS

- Persistence:
    - Windows - schtasks
    - Linux - XDG
    - Darwin - launchd

- Interaction:
    - Bichiterpreter (Job Based): exec (using os.exec)
    - Inject Launchers (using os.exec)
    - Rev SSH

