<?php
require(__DIR__ . '/Base62.php');

class headerToken
{
    public function verifyToken(string $providedToken, string $secretKey)
    {
        debug("  token given => " . $providedToken);
        debug("secret given  => " . $secretKey);

        try {
            $payload = JWT::decode($providedToken, $secretKey);
            debug('payload', $payload);
        } catch (Exception $e) {
            debug($e->getMessage());
            return false;
        }
        return $payload;


    }

    public function mkToken(string $public, string $secretKey): string
    {
        return Base62::encode(hash_hmac('md5', $public . ':', $secretKey));
    }
}