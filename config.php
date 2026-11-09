<?php
require_once("classes/Connect.php");
require_once("classes/dataHandler.php");
require_once("classes/SQLify.php");
require_once("classes/functions.php");
require_once('jwt.php');
ini_set('display_errors', 'Off'); // ne jamais injecter d'erreurs dans la reponse JSON
error_reporting(-1); // ... mais tout journaliser via error_log

// GET details
$my_config = (include 'details.php');

// create all classes
$connect = new Connect($my_config["database"]);
try {
    $data = new DataHandler($my_config, $connect);
    if ($data->statementPass)
        $sql = new SQLify($data);

    $data->controlParams();
} catch (Exception $e) {
    if ($e->getCode() != 1001)
        error_log($e->getMessage());
}
