<?php
/**
 * Standalone Magento module blacklist check script. This is equivalent to the single-line command in the readme.
 *
 * Don't use this script. Follow the README instructions.
 *
 * @see    https://github.com/gwillem/magento1-module-blacklist
 * @author Ryan Hoerr <rhoerr@gmail.com>
 */

require_once('app/Mage.php');
Mage::app();

$config = Mage::getConfig()->getNode()->modules;
$found = array();
$list = fopen('https://raw.githubusercontent.com/gwillem/magevulndb/master/magento1-vulnerable-extensions.csv', 'r');
while ($list && list($name, $version) = list($row['module'], $row['fixed_in'], , $row['reference'], $row['update']) = fgetcsv($list)) {
	if (isset($name, $version, $config->{$name}->version)
		&& (empty($version) || version_compare($config->{$name}->version, $version, '<'))) {
		$found[] = $row;
	}
}

if ($found) {
	echo 'Found possible vulnerable modules: '.print_r($found, 1);
	exit(1);
}

echo 'No known vulnerable modules detected.';
exit(0);
