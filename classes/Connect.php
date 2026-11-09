<?php

class Connect
{
    protected $db;
    public $connectInfo;
    public $obj;
    private $array;

    /**
     * Constructor
     * @param $dsn string The dsn to the database-file
     * @return void
     */
    public
    function __construct($obj)
    {
        // Server
        $this->obj = $obj;
        $this->array = array(
            "dsn" => "mysql:host=$obj[host];dbname=$obj[dbname]",
            "login" => "$obj[username]",
            "password" => "$obj[password]",
            "options" => array(PDO::MYSQL_ATTR_INIT_COMMAND => "SET NAMES 'UTF8'"),
        );
        $databaseConfig = $this->array;

        try {
            $db = new PDO(...array_values($databaseConfig));
            $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
            $this->db = $db;
        } catch (PDOException $e) {
            print "Error!: " . $e->getMessage() .
                "<br/>";
            throw new PDOException("Could not connect to database, hiding details.");
        }
    }

    public
    function startResponse($data, $sql)
    {
        if (!is_object($data)) return;
        if (!$data->statementPass &&
            (!array_key_exists('statement', $data->params) || $data->params["statement"] !== "login")) {
            debug('[startResponse] 401', $data->params);
            http_response_code(401);
            return json_encode(array('info' => $data->loginInfo['login']['error']));
        }
        // Based on method, do GET, POST, PUT, DELETE
        switch ($data->method) {
            case 'GET':
                debug('handing GET response', $data->loginInfo, $sql);
                $this->connectInfo['login'] = $data->loginInfo['login'];
                return $this->jsonResponse($sql->sql, null, returnInfo($data, $sql, $this), $data);
            case 'POST':
                debug('handing POST response', $data);
                if (array_key_exists('statement', $data->params) and $data->params["statement"] === "login"
                    and getPOST('username') and getPOST('password')) {
                    debug('[startResponse] starting login process');
                    $this->connectInfo['login'] = $data->loginJwt($this);
                    // return $this->jsonResponse($sql->sql['GET'], $data->sqlParams, returnInfo($data, $sql, $this), $data);
                    debug('login result: ', $this->connectInfo);
                    if (array_key_exists('error', $this->connectInfo['login'])) {
                        http_response_code(401);
                    }
                    return json_encode($this->connectInfo['login']);
                } elseif (isset($data->params["token"])) {
                    if ($data->statementPass) {
                        $this->connectInfo['login'] = $data->loginInfo['login'];
                        $this->execute($sql->sql['POST']);
                    }
                    $this->connectInfo['login'] = $data->loginInfo['login'];
                    if (array_key_exists('lastInsertId', $this->connectInfo) && !empty($this->connectInfo['lastInsertId']))
                        return $this->jsonResponse("SELECT * FROM `" . $data->table . "` WHERE " . $data->idCol . " = " . $this->connectInfo['lastInsertId']);
                    else {
                        debug('last insert: ', $this->connectInfo);
                        return $this->jsonResponse("SELECT NOW()");
                    }
                } elseif ($data->external_auth) {
                    debug('external auth, executing sql', $sql);
                    $this->execute($sql->sql['POST']);
                    if (array_key_exists('lastInsertId', $this->connectInfo) && !empty($this->connectInfo['lastInsertId']))
                        return $this->jsonResponse("SELECT * FROM `" . $data->table . "` WHERE " . $data->idCol . " = " . $this->connectInfo['lastInsertId']);
                    else {
                        debug('last insert: ', $this->connectInfo);
                        return $this->jsonResponse("SELECT NOW()");
                    }
                }
                break;
            case 'PUT':
                debug('handing PUT response');
                $data->putParams = array_values(array_filter($data->putParams, function ($v) {
                    return !is_null($v);
                }));
                $updatable = array_diff(array_keys($data->posts), array($data->idCol));
                if (empty($updatable)) {
                    http_response_code(400);
                    return json_encode(array('info' => 'PUT: no field to update'));
                }
                if (empty($data->params['filter']) && !array_key_exists($data->idCol, $data->posts)) {
                    http_response_code(400);
                    return json_encode(array('info' => 'PUT: missing id column "' . $data->idCol . '"'));
                }
                $this->execute($sql->sql, $data->putParams);
                return $this->jsonResponse("SELECT * FROM `$data->table` WHERE $data->idCol=" . end($data->putParams));
            case 'DELETE':
                debug('handing DELETE response');
                debug(print_r($data->sqlParams, true));
                $this->execute($sql->sql, $data->sqlParams);
                if (0 !== $this->connectInfo['executeStatus']) {
                    http_response_code(599 /* custom */);
                    return json_encode(array('info' => $this->connectInfo));
                } else
                    return $this->jsonResponse("SELECT * FROM `$data->table`");
        }
    }

    public
    function execute($sql, $sqlParams = null)
    {
        $stmt = false;
        try {
            debug('[execute] ', $sql);
            debug('[execute] ', $sqlParams);
            $stmt = $this->db->prepare($sql);
            if ($stmt === false) {
                debug('error on sql query', $this->db->errorInfo());
                $this->connectInfo['executeStatus'] = $this->db->errorCode();
                $this->connectInfo['executeMessage'] = $this->db->errorInfo()[0];
                return;
            }
            if ($stmt->execute($sqlParams) === true) {
                debug($sql . ' <== SUCCESS');
                $this->connectInfo['executeMessage'] = "Successful";
                $this->connectInfo['executeStatus'] = 0;
                $this->connectInfo['lastInsertId'] = $this->db->lastInsertId();
            } else {
                debug('error on sql query', $stmt->errorInfo());
                $this->connectInfo['executeStatus'] = $stmt->errorCode();
            }
        } catch (PDOException $e) {
            debug('Exception SQL', $e->getMessage());
            $this->connectInfo['executeStatus'] = $stmt instanceof PDOStatement ? $stmt->errorCode() : $e->getCode();
            $this->connectInfo['executeMessage'] = $e->getMessage();
        } catch (Exception $e) {
            $this->connectInfo['executeStatus'] = $stmt instanceof PDOStatement ? $stmt->errorCode() : $e->getCode();
            $this->connectInfo['executeMessage'] = $e->getMessage();
        }
    }

    public
    function rowCount($sql)
    {
        $stmt = $this->db->prepare($sql);
        $stmt->execute();
        return $stmt->rowCount();
    }

    // Fetches from MySQL DB and returns as JSON
    public
    function jsonResponse($sql, $sqlParams = null, $info = null, $data = null)
    {

        if (@is_null(@$data->tableProperty["select"]) or
            (!isset($this->connectInfo) && isset($data) && !isset($data->login)) or
            (@$this->connectInfo['login'] and @$data->tableProperty['select'] >= @$this->connectInfo['login']->authorityLevel)) {
            $stmt = $this->db->prepare($sql);
            try {
                $stmt->execute($sqlParams);
            } catch (PDOException $e) {
                return json_encode(array('info' => $e->getMessage(), 'stack' => $e->getTraceAsString(), 'request' => $sql));
            }
            //info added page number, id etc.
            return json_encode(
                array('info' => $info, 'data' => $stmt->fetchAll(PDO::FETCH_ASSOC)),
                JSON_PRETTY_PRINT
            );
        } else {
            debug('table level: ', @$data->tableProperty);
            debug('login level: ', @$this->connectInfo['login']);
            $info['error'] = "Authority level not enough to get answer";
            return json_encode(array('info' => $info));
        }
    }

    // get res with one fetch
    public
    function fetchArray($sql)
    {
        $stmt = $this->db->prepare($sql);
        $stmt->execute();
        return $stmt->fetchAll(PDO::FETCH_COLUMN);
    }

    // get res with one fetch
    public
    function fetchOneRow($sql, $executeArray = null)
    {
        $stmt = $this->db->prepare($sql);
        $stmt->execute($executeArray);
        return $stmt->fetch(PDO::FETCH_ASSOC);
    }
}
