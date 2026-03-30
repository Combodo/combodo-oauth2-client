<?php return array(
    'root' => array(
        'name' => 'combodo/combodo-oauth2-client',
        'pretty_version' => '1.0.0+no-version-set',
        'version' => '1.0.0.0',
        'reference' => null,
        'type' => 'itop-extension',
        'install_path' => __DIR__ . '/../../',
        'aliases' => array(),
        'dev' => true,
    ),
    'versions' => array(
        'combodo/combodo-oauth2-client' => array(
            'pretty_version' => '1.0.0+no-version-set',
            'version' => '1.0.0.0',
            'reference' => null,
            'type' => 'itop-extension',
            'install_path' => __DIR__ . '/../../',
            'aliases' => array(),
            'dev_requirement' => false,
        ),
        'hybridauth/hybridauth' => array(
            'pretty_version' => 'dev-master',
            'version' => 'dev-master',
            'reference' => 'da3cd2132dead3078b61dba80ae2c45226b53dd6',
            'type' => 'library',
            'install_path' => __DIR__ . '/../hybridauth/hybridauth',
            'aliases' => array(
                0 => '9999999-dev',
            ),
            'dev_requirement' => false,
        ),
    ),
);
