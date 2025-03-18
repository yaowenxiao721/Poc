# Exploit Title: Concretecms v9.3.9 - Cross-Site Scripting (XSS)
## Date: 3/13/2025
## Vendor Homepage: https://github.com/concretecms/concretecms
## Tested on: Debian Linux, Apache, Mysql
## Vendor: Concretecms
## Version: v9.3.9
## Exploit Description:
## ConcreteCMS v9.3.9 suffers from a Stored Cross-Site Scripting (XSS) vulnerability in the Paragraph Source field when adding a Feature block. This vulnerability allows attackers to cheat other users by injecting malicious scripts into web pages viewed by other users.

## ---------------------------------POC-----------------------------

```
<script>alert('Source');</script>
```

1. Log in as a user with page editing privileges.
2. Click "add content to the page" in the top navigation.
3. Select the Feature block , drag and drop it to the page.
4. Add <script>alert('Source');</script> to the Paragraph Source field and then click ADD,the xss vulnerability appears.

Potentially problematic source code:
```php
public function save($args)
    {
        switch (isset($args['linkType']) ? intval($args['linkType']) : 0) {
            case 1:
                $args['externalLink'] = '';
                break;
            case 2:
                $args['internalLinkCID'] = 0;
                break;
            default:
                $args['externalLink'] = '';
                $args['internalLinkCID'] = 0;
                break;
        }
        $args['paragraph'] = isset($args['paragraph']) ? LinkAbstractor::translateTo($args['paragraph']) : '';
        /** @var SanitizeService $security */
        $security = $this->app->make('helper/security');
        $args['icon'] = isset($args['icon']) ? $security->sanitizeString($args['icon']) : '';
        $args['title'] = isset($args['title']) ? $security->sanitizeString($args['title']) : '';
        $args['titleFormat'] = isset($args['titleFormat']) ? $security->sanitizeString($args['titleFormat']) : '';
        $args['internalLinkCID'] = isset($args['internalLinkCID']) ? $security->sanitizeInt($args['internalLinkCID']) : 0;
        $args['externalLink'] = isset($args['externalLink']) ? $security->sanitizeURL($args['externalLink']) : '';
        unset($args['linkType']);

        $args = $args + [
            'fID' => 0,
        ];
        $args['fID'] = $args['fID'] != '' ? $args['fID'] : 0;
        parent::save($args);
    }
```