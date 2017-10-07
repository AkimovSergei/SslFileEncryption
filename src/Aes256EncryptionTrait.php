<?php

namespace Sa\SslFileEncryption;

use Sa\SslFileEncryption\Exceptions\FileNotFoundException;
use Sa\SslFileEncryption\Exceptions\FileNotWritableException;

/**
 * Trait Aes256EncryptionTrait
 *
 * @package Sa\SslFileEncryption
 */
trait Aes256EncryptionTrait
{

    use EncryptionTrait;

    /**
     * Key size
     *
     * @return int
     */
    public function getKeySize()
    {
        return 32;
    }

    /**
     * Cipher
     *
     * @return string
     */
    public function getCipher()
    {
        return 'aes-256-cbc';
    }

    /**
     * Get file contents
     *
     * @return bool|string
     * @throws FileNotFoundException
     */
    public function fileGetContents()
    {
        if (!file_exists($this->getFullPathAttribute())) {
            throw new FileNotFoundException("File not found");
        }

        return file_get_contents($this->getFullPathAttribute());
    }


    /**
     * Encrypt
     *
     * @param $userId
     * @param int $expiryDuration
     * @return string
     * @throws FileNotWritableException
     */
    public function encrypt($userId, $expiryDuration = 1)
    {

        /*
         * Encrypted content
         */
        $encrypted = openssl_encrypt($this->fileGetContents(), $this->getCipher(), $this->getKey(), $this->getOptions(), $this->getIV());

        $basePath = public_path($this->path);

        /*
         * Encrypted file path
         */
        $encryptedPath = $basePath . DIRECTORY_SEPARATOR . md5(str_random());

        $encryptedFile = $encryptedPath . DIRECTORY_SEPARATOR . $this->name;
        $keyFile = $encryptedPath . DIRECTORY_SEPARATOR . 'key.txt';
        $ivFile = $encryptedPath . DIRECTORY_SEPARATOR . 'iv.txt';
        $metaFile = $encryptedPath . DIRECTORY_SEPARATOR . 'meta.json';
        $zipFile = $basePath . DIRECTORY_SEPARATOR . $this->name . '.zip';

        /*
         * Create Directory
         */
        if (!file_exists($encryptedPath)) {
            mkdir($encryptedPath);
        }

        /*
         * Save encrypted file
         */
        $fp = fopen($encryptedFile, 'wb');

        if (!fwrite($fp, $encrypted)) {
            throw new FileNotWritableException("Could not write file " . $encryptedFile);
        }

        fclose($fp);

        /*
         * Keep key and meta
         */
        try {
            \File::put($keyFile, $this->getKey());
            \File::put($ivFile, $this->getIV());
            \File::put($metaFile, json_encode($this->generateMeta($expiryDuration)));
        } catch (\Exception $ex) {

        }

        $pwd = $this->getEncryptionPassword($userId);

        /*
         * Create zip with password
         */
        exec("zip -j -P {$pwd} {$zipFile} {$encryptedFile} {$keyFile} {$ivFile} {$metaFile} 2>&1");

        /*
         * Remove temporary files
         */
        unlink($encryptedFile);
        unlink($keyFile);
        unlink($ivFile);
        unlink($metaFile);
        rmdir($encryptedPath);

        return $zipFile;
    }

    /**
     *
     */
    public function decrypt()
    {
//        $contents = $this->_sourceFile->getFileContents();
//        $parts = explode(':', $contents);
//
//        $decrypted = openssl_decrypt(array_shift($parts), static::AES_256_CBC, $this->getKey(), $this->getOptions(), $this->getIV());
//
//        $encryptedFile = new File($destination ? $destination : 'encrypted/' . date('Y-m-d H:i:s'));
//        $encryptedFile->save($encryptedFile, $decrypted);
//
//        return $encryptedFile->getFilePath();
    }

    /**
     * Get encrypted password
     *
     * @param $user
     * @return string
     */
    protected function getEncryptionPassword($user)
    {
        return sha1($user->id . $this->id);
    }

    /**
     * Generate meta array
     *
     * @param $expiryDuration
     * @return array
     */
    public function generateMeta($expiryDuration)
    {
        return [
            'expiry' => [
                'generated_at' => \Carbon\Carbon::now()->toDateTimeString(),
                'expires_at' => \Carbon\Carbon::now()->addDays($expiryDuration)->toDateTimeString(),
                'expiry_days_count' => $expiryDuration,
            ],
        ];
    }

}