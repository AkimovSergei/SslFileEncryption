<?php
/**
 * Created by PhpStorm.
 * User: sergeiakimov
 * Date: 9/13/17
 * Time: 8:41 PM
 */

namespace Sa\SslFileEncryption;


trait EncryptionTrait
{

    /**
     * @var
     */
    protected $key;

    /**
     * Initialisation vector
     *
     * @var
     */
    protected $iv;

    /**
     * Encryption/Decryption options
     *
     * @var
     */
    protected $options;

    /**
     * Key size
     *
     * @return mixed
     */
    abstract public function getKeySize();

    /**
     * Cipher
     *
     * @return mixed
     */
    abstract public function getCipher();

    /**
     * Encrypt file
     *
     * @return mixed
     */
    abstract public function encrypt();

    /**
     * Decrypt file
     *
     * @return mixed
     */
    abstract public function decrypt();

    /**
     * Get file contents
     *
     * @return mixed
     */
    abstract public function fileGetContents();

    /**
     * Full path
     *
     * @return mixed
     */
    abstract public function getFullPathAttribute();

    /**
     * Get key
     *
     * @return mixed
     */
    public function getKey()
    {
        if (is_null($this->key)) {
            $this->generateKey();
        }
        return $this->key;
    }

    /**
     * Get Initialisation vector
     *
     * @return mixed
     */
    public function getIV()
    {
        if (is_null($this->iv)) {
            $this->generateIV();
        }
        return $this->iv;
    }

    /**
     * Get options
     *
     * @return int
     */
    public function getOptions()
    {
        return $this->options;
    }

    /**
     * Set encryption options
     *
     * @param $options
     */
    public function setOptions($options)
    {
        $this->options = $options;
    }

    /**
     * Generate random key
     *
     * @return string
     */
    protected function generateKey()
    {
        return $this->key = openssl_random_pseudo_bytes($this->getKeySize());
    }

    /**
     * Generate Initialisation vector
     *
     * @return string
     */
    protected function generateIV()
    {
        return $this->iv = openssl_random_pseudo_bytes(openssl_cipher_iv_length($this->getCipher()));
    }

    /**
     * Get the instance as an array.
     *
     * @return array
     */
    public function toArray()
    {
        return [
            'key' => $this->getKey(),
            'iv' => $this->getIV(),
            'options' => $this->getOptions(),
        ];
    }


}