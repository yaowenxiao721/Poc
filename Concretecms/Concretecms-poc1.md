# Exploit Title: Concretecms v9.3.9 - Cross-Site Scripting (XSS)
## Date: 3/10/2025
## Vendor Homepage: https://github.com/concretecms/concretecms
## Tested on: Debian Linux, Apache, Mysql
## Vendor: Concretecms
## Version: v9.3.9
## Exploit Description:
## ConcreteCMS v9.3.9 suffers from a Stored Cross-Site Scripting (XSS) vulnerability in the Question field when adding a Legacy Form block. This vulnerability allows attackers to cheat other users by injecting malicious scripts into web pages viewed by other users.

## ---------------------------------POC-----------------------------

```
<script>alert('XSS');</script>
```
1. Log in as a user with page editing privileges.
2. Click "add content to the page" in the top navigation.
3. Select the Legacy Form block , drag and drop it to the page.
4. Add <script>alert('Question');</script> to the question field and then click add question bottons,the xss vulnerability appears.

Potentially problematic source code:
```php
if ($pendingEditExists) {
                $width = $height = 0;
                if ($values['inputType'] == 'text') {
                    $width = $this->limitRange((int) ($values['width']), 20, 500);
                    $height = $this->limitRange((int) ($values['height']), 1, 100);
                }
                $dataValues = [
                    (int) ($values['qsID']),
                    trim($values['question']),
                    $values['inputType'],
                    $values['options'],
                    (int) ($values['position']),
                    $width,
                    $height,
                    (int) ($values['required']),
                    $values['defaultDate'],
                    (int) ($values['msqID']),
                ];
                $sql = 'UPDATE btFormQuestions SET questionSetId=?, question=?, inputType=?, options=?, position=?, width=?, height=?, required=?, defaultDate=? WHERE msqID=? AND bID=0';
            } 
```

Patch:
```php
public function addEditQuestion($values, $withOutput = 1)
{
    $jsonVals = [];
    $values['options'] = h($values['options']); // patch XSS
    if (strtolower($values['inputType']) == 'undefined') {
        $values['inputType'] = 'field';
    }

    if ((int) ($values['qsID']) == 0) {
        $values['qsID'] = time();
    }

    if (strlen($values['question']) == 0 || strlen($values['inputType']) == 0 || $values['inputType'] == 'null') {
        $jsonVals['success'] = 0;
        $jsonVals['noRequired'] = 1;
    } else {
        if ((int) ($values['msqID'])) {
            $jsonVals['mode'] = '"Edit"';
            $pendingEditExists = $this->db->fetchColumn(
                'SELECT COUNT(*) FROM btFormQuestions WHERE bID=0 AND msqID=?',
                [(int) $values['msqID']]
            );

            $jsonVals['hideQID'] = (int) ($this->db->fetchColumn(
                'SELECT MAX(qID) FROM btFormQuestions WHERE bID!=0 AND msqID=?',
                [(int) $values['msqID']]
            ));
        } else {
            $jsonVals['mode'] = '"Add"';
            $pendingEditExists = false;
        }

        if ($values['inputType'] == 'email') {
            $options = ['send_notification_from' => isset($values['send_notification_from']) ? 1 : 0];
            $values['options'] = serialize($options);
        }

        if ($pendingEditExists) {
            $width = $height = 0;
            if ($values['inputType'] == 'text') {
                $width = $this->limitRange((int) $values['width'], 20, 500);
                $height = $this->limitRange((int) $values['height'], 1, 100);
            }
            $sql = 'UPDATE btFormQuestions 
                    SET questionSetId=?, question=?, inputType=?, options=?, position=?, width=?, height=?, required=?, defaultDate=? 
                    WHERE msqID=? AND bID=0';
            $dataValues = [
                (int) $values['qsID'],
                h(trim($values['question'])),
                $values['inputType'],
                $values['options'],
                (int) $values['position'],
                $width,
                $height,
                (int) $values['required'],
                $values['defaultDate'],
                (int) $values['msqID'],
            ];
        } else {
            if (!isset($values['position'])) {
                $values['position'] = 1000;
            }
            if (!(int) ($values['msqID'])) {
                $values['msqID'] = (int) ($this->db->fetchColumn('SELECT MAX(msqID) FROM btFormQuestions') + 1);
            }
            $sql = 'INSERT INTO btFormQuestions (msqID,questionSetId,question,inputType,options,position,width,height,required,defaultDate) 
                    VALUES (?,?,?,?,?,?,?,?,?,?)';
            $dataValues = [
                (int) $values['msqID'],
                (int) $values['qsID'],
                h(trim($values['question'])), // patch XSS
                $values['inputType'],
                $values['options'],
                (int) $values['position'],
                (int) $values['width'],
                (int) $values['height'],
                (int) $values['required'],
                $values['defaultDate'],
            ];
        }
        $this->db->executeQuery($sql, $dataValues);
        $this->lastSavedMsqID = (int) $values['msqID'];
        $this->lastSavedqID = (int) ($this->db->fetchColumn('SELECT MAX(qID) FROM btFormQuestions WHERE bID=0 AND msqID=?', [(int) $values['msqID']]));
        $jsonVals['qID'] = $this->lastSavedqID;
        $jsonVals['success'] = 1;
    }

    $jsonVals['qsID'] = $values['qsID'];
    $jsonVals['msqID'] = (int) ($values['msqID']);
    if ($withOutput) {
        echo json_encode($jsonVals); 
    }
}

```