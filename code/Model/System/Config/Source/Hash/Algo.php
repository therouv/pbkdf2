<?php

class Ikonoshirt_Pbkdf2_Model_System_Config_Source_Hash_Algo
{
    /**
     * Retrive the hash algorithms as option array
     *
     * @return array
     */
    public function toOptionArray()
    {
        $options = array();
        foreach (hash_algos() as $algo) {
            $options[] = array('value' => $algo, 'label' => strtoupper($algo));
        }
        return $options;
    }
}
