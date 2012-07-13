<?php

class Ikonoshirt_Pbkdf2_Model_Stub_CE
    extends Mage_Core_Model_Encryption
    implements Ikonoshirt_Pbkdf2_Model_Stub_Interface
{
    /**
     * Model with implemented logic
     *
     * @var Ikonoshirt_Pbkdf2_Model_Encryption
     */
    protected $_realHashModel;

    /**
     * Class constructor
     *
     * @return void
     */
    public function __construct()
    {
        $this->_realHashModel = Mage::getModel('ikonoshirt_pbkdf2/encryption', array($this));
    }

    /**
     * (non-PHPdoc)
     * @see Ikonoshirt_Pbkdf2_Model_Stub_Interface::validateHash()
     */
    public function validateHash($password, $hash)
    {
        return $this->_realHashModel->validateHash($password, $hash);
    }

    /**
     * (non-PHPdoc)
     * @see Ikonoshirt_Pbkdf2_Model_Stub_Interface::getHash()
     */
    public function getHash($password, $salt = false)
    {
        return $this->_realHashModel->getHash($password, $salt);
    }

    /**
     * (non-PHPdoc)
     * @see Ikonoshirt_Pbkdf2_Model_Stub_Interface::getHelper()
     */
    public function getHelper()
    {
        return $this->_helper;
    }

    /**
     * (non-PHPdoc)
     * @see Ikonoshirt_Pbkdf2_Model_Stub_Interface::validateLegacyHash()
     */
    public function validateLegacyHash($password, $hash)
    {
        return parent::validateHash($password, $hash);
    }
}
