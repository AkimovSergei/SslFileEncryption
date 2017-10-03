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
     * @throws \Exception
     */
    public function encrypt($userId, $expiryDuration = 1)
    {


        $basePath = public_path($this->path);

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

        $inputHandle = @\fopen($this->getFullPathAttribute(), 'rb');
        $outputHandle = @\fopen($encryptedFile, 'wb');

        $inputStat = \fstat($inputHandle);
        $inputSize = $inputStat['size'];

        /* Loop until we reach the end of the input file. */
        $atFileEnd = false;
        while (!(\feof($inputHandle) || $atFileEnd)) {

            /* Find out if we can read a full buffer, or only a partial one. */
            /** @var int */
            $pos = \ftell($inputHandle);

            if (!\is_int($pos)) {
                throw new \Exception(
                    'Could not get current position in input file during encryption'
                );
            }

            if ($pos + 1048576 >= $inputSize) {
                /* We're at the end of the file, so we need to break out of the loop. */
                $atFileEnd = true;
                $read = self::readBytes(
                    $inputHandle,
                    $inputSize - $pos
                );
            } else {
                $read = self::readBytes(
                    $inputHandle,
                    1048576
                );
            }

            /* Encrypt this buffer. */
            /** @var string */
            $encrypted = \openssl_encrypt(
                $read,
                $this->getCipher(),
                $this->getKey(),
                $this->getOptions(), // OPENSSL_RAW_DATA
                $this->getIV()
            );

            if (!\is_string($encrypted)) {
                throw new \Exception(
                    'OpenSSL encryption error'
                );
            }

            /* Write this buffer's ciphertext. */
            self::writeBytes($outputHandle, $encrypted, mb_strlen($encrypted));

        }

        \fclose($inputHandle);
        \fclose($outputHandle);

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
     * Write to a stream; prevents partial writes.
     *
     * @param resource $stream
     * @param string $buf
     * @param int $num_bytes
     * @return int
     *
     * @throws \Exception
     */
    public static function writeBytes($stream, $buf, $num_bytes = null)
    {
        $bufSize = mb_strlen($buf);
        if ($num_bytes === null) {
            $num_bytes = $bufSize;
        }
        if ($num_bytes > $bufSize) {
            throw new \Exception(
                'Trying to write more bytes than the buffer contains.'
            );
        }
        if ($num_bytes < 0) {
            throw new \Exception(
                'Tried to write less than 0 bytes'
            );
        }
        $remaining = $num_bytes;
        while ($remaining > 0) {
            /** @var int $written */
            $written = \fwrite($stream, $buf, $remaining);
            if (!\is_int($written)) {
                throw new \Exception(
                    'Could not write to the file'
                );
            }
            $buf = (string)static::ourSubstr($buf, $written, null);
            $remaining -= $written;
        }
        return $num_bytes;
    }


    /**
     * Read from a stream; prevent partial reads.
     *
     * @param resource $stream
     * @param int $num_bytes
     * @return string
     *
     * @throws \Exception
     */
    public static function readBytes($stream, $num_bytes)
    {
        if ($num_bytes < 0) {
            throw new \Exception(
                'Tried to read less than 0 bytes'
            );
        } elseif ($num_bytes === 0) {
            return '';
        }

        $buf = '';
        $remaining = $num_bytes;

        while ($remaining > 0 && !\feof($stream)) {

            /** @var string $read */
            $read = \fread($stream, $remaining);

            if (!\is_string($read)) {
                throw new \Exception(
                    'Could not read from the file'
                );
            }

            $buf .= $read;
            $remaining -= static::ourStrlen($read);

        }

        if (static::ourStrlen($buf) !== $num_bytes) {
            throw new \Exception(
                'Tried to read past the end of the file '
            );
        }

        return $buf;
    }


    /**
     * Computes the length of a string in bytes.
     *
     * @param string $str
     *
     * @return int
     */
    public static function ourStrlen($str)
    {
        static $exists = null;
        if ($exists === null) {
            $exists = \function_exists('mb_strlen');
        }
        if ($exists) {
            $length = \mb_strlen($str, '8bit');
            if ($length === false) {
                throw new \Exception();
            }
            return $length;
        } else {
            return \strlen($str);
        }
    }

    /**
     * Behaves roughly like the function substr() in PHP 7 does.
     *
     * @param string $str
     * @param int $start
     * @param int $length
     *
     *
     * @return string|bool
     */
    public static function ourSubstr($str, $start, $length = null)
    {
        static $exists = null;
        if ($exists === null) {
            $exists = \function_exists('mb_substr');
        }

        if ($exists) {
            // mb_substr($str, 0, NULL, '8bit') returns an empty string on PHP
            // 5.3, so we have to find the length ourselves.
            if (!isset($length)) {
                if ($start >= 0) {
                    $length = static::ourStrlen($str) - $start;
                } else {
                    $length = -$start;
                }
            }

            // This is required to make mb_substr behavior identical to substr.
            // Without this, mb_substr() would return false, contra to what the
            // PHP documentation says (it doesn't say it can return false.)
            if ($start === static::ourStrlen($str) && $length === 0) {
                return '';
            }

            if ($start > static::ourStrlen($str)) {
                return false;
            }

            $substr = \mb_substr($str, $start, $length, '8bit');
            if (static::ourStrlen($substr) !== $length) {
                throw new \Exception(
                    'Your version of PHP has bug #66797. Its implementation of
                    mb_substr() is incorrect. See the details here:
                    https://bugs.php.net/bug.php?id=66797'
                );
            }
            return $substr;
        }

        // Unlike mb_substr(), substr() doesn't accept NULL for length
        if (isset($length)) {
            return \substr($str, $start, $length);
        } else {
            return \substr($str, $start);
        }
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
     * @param $userId
     * @return string
     */
    protected function getEncryptionPassword($userId)
    {
        return sha1($userId . $this->id);
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
