<?php

class Ikonoshirt_Pbkdf2_Model_Encryption
{
    /**
     * pbkdf2 iterations
     * default 10000
     *
     * @var integer
     */
    protected $_iterations;

    /**
     * pbkdf2 hash algorithm
     * default sha512
     *
     * @var string
     */
    protected $_hashAlgorithm;

    /**
     * pbkdf2 key length
     * default 256
     *
     * @var integer
     */
    protected $_keyLengt;

    /**
     * pbkdf2 salt length
     * default 16, should be at least 8
     *
     * @var integer
     */
    protected $_saltLength;

    /**
     * pbkdf2 legacy check to support old md5 hashes
     * default false
     *
     * @var boolean
     */
    protected $_checkLegacy;

    /**
     * the stub which is used to replace the old encryption model
     *
     * @var Ikonoshirt_Pbkdf2_Model_Stub_Interface
     */
    protected $_encryptionStub;

    /**
     * overwrite default attributes with configuration settings
     *
     * @param array $arguments
     * @return \Ikonoshirt_Pbkdf2_Model_Encryption
     */
    public function __construct(array $arguments)
    {
        $this->_encryptionStub = $arguments[0];
        $this->_iterations = (int) Mage::getStoreConfig('ikonoshirt/pbkdf2/iterations');
        $this->_hashAlgorithm = Mage::getStoreConfig('ikonoshirt/pbkdf2/hash_algorithm');
        $this->_keyLength = (int)Mage::getStoreConfig('ikonoshirt/pbkdf2/key_length');
        $this->_saltLength = (int)Mage::getStoreConfig('ikonoshirt/pbkdf2/salt_length');
        $this->_checkLegacy = (boolean)Mage::getStoreConfig('ikonoshirt/pbkdf2/check_legacy_hash');
    }

    /**
     * Generate a [salted] hash.
     *
     * $salt can be:
     * false - old Mage_Core_Model_Encryption::hash() function will be used
     * integer - a random with specified length will be generated
     * string - use the given salt for _pbkdf2
     *
     * @param string $plaintext
     * @param mixed $salt
     * @return string
     */
    public function getHash($plaintext, $salt = false)
    {
        if (false === $salt) {
            // if no salt was passed, use the old method
            return $this->_encryptionStub->hash($plaintext);
        }

        if (is_integer($salt)) {
            // check for minimum length
            if ($salt < $this->_saltLength) {
                $salt = $this->_saltLength;
            }
            $salt = $this->_encryptionStub->getHelper()->getRandomString($salt);
        }

        return $this->_pbkdf2($this->_hashAlgorithm, $plaintext, $salt, $this->_iterations, $this->_keyLength) . ':' . $salt;
    }

    /**
     * Validate hash against hashing method (with or without salt)
     *
     * @param string $password
     * @param string $hash
     * @return boolean
     * @throws Mage_Core_Exception
     */
    public function validateHash($password, $hash)
    {
        $hashArr = explode(':', $hash);
        switch (count($hashArr)) {
            case 1:
                return $this->hash($password) === $hash;
            case 2:
                if ($this->_pbkdf2($this->_hashAlgorithm, $password, $hashArr[1], $this->_iterations, $this->_keyLength)
                    === $hashArr[0]
                ) {
                    return true;
                }
                // if the password is not pbkdf2 hashed, and the owner wants it, try the old hashing algorithm
                return $this->_checkLegacy && $this->_encryptionStub->validateLegacyHash($password, $hash);
        }
        Mage::throwException('Invalid hash.');
    }

    /**
     * PBKDF2 key derivation function as defined by RSA's PKCS #5: https://www.ietf.org/rfc/rfc2898.txt
     *
     * Test vectors can be found here: https://www.ietf.org/rfc/rfc6070.txt
     *
     * This implementation of PBKDF2 was originally created by defuse.ca
     * With improvements by variations-of-shadow.com
     *
     * @param string  $algorithm The hash algorithm to use. Recommended: SHA256
     * @param string  $password  The password.
     * @param string  $salt      A salt that is unique to the password.
     * @param integer $count     Iteration count. Higher is better, but slower. Recommended: At least 1024.
     * @param integer $keyLength The length of the derived key in bytes.
     * @param boolean $rawOutput If true, the key is returned in raw binary format. Hex encoded otherwise.
     *
     * @return string A $keyLenght-byte key derived from the password and salt.
     */
    protected function _pbkdf2($algorithm, $password, $salt, $count, $keyLength, $rawOutput = false)
    {
        $algorithm = strtolower($algorithm);
        if (!in_array($algorithm, hash_algos(), true)) {
            Mage::throwException('PBKDF2 ERROR: Invalid hash algorithm ' . $algorithm);
        }
        if ($count <= 0 || $keyLength <= 0) {
            Mage::throwException('PBKDF2 ERROR: Invalid parameters.');
        }

        $hashLength = strlen(hash($algorithm, "", true));
        $blockCount = ceil($keyLength / $hashLength);

        // See Section 5.2 of the RFC 2898
        if ($keyLength > (pow(2, 32) -1) * $hashLength) {
            Mage::throwException('PBKDF2 ERROR: Invalid parameter: derived key too long.');
        }

        $output = "";
        for ($i = 1; $i <= $blockCount; $i++) {
            // $i encoded as 4 bytes, big endian.
            $last = $salt . pack("N", $i);
            // first iteration
            $last = $xorsum = hash_hmac($algorithm, $last, $password, true);
            // perform the other $count - 1 iterations
            for ($j = 1; $j < $count; $j++) {
                $xorsum ^= ($last = hash_hmac($algorithm, $last, $password, true));
            }
            $output .= $xorsum;
        }

        if ($rawOutput) {
            return substr($output, 0, $keyLength);
        } else {
            return bin2hex(substr($output, 0, $keyLength));
        }
    }
}
