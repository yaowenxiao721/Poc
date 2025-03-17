# Exploit Title: Concretecms v9.3.9 - Cross-Site Scripting (XSS)
## Date: 3/13/2025
## Vendor Homepage: https://github.com/concretecms/concretecms
## Tested on: Debian Linux, Apache, Mysql
## Vendor: Concretecms
## Version: v9.3.9
## Exploit Description:
## ConcreteCMS v9.3.9 suffers from a Stored Cross-Site Scripting (XSS) vulnerability in the Title Text field when adding a Page Attribute Display block. This vulnerability allows attackers to cheat other users by injecting malicious scripts into web pages viewed by other users.

## ---------------------------------POC-----------------------------

```
<script>alert('Title Text');</script>

```

1. Use administrator login
2. Click "add content to the page" in the top navigation.
3. Select the Page Attribute Display block , drag and drop it to the page.
4. Add <script>alert('Title Text');</script> to the Title Text field and then click ADD,the xss vulnerability appears.

