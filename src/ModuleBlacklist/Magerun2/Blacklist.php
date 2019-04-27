<?php
/**
 * Magerun2 plugin: Scan the current Magento 2 installation for known vulnerable modules.
 *
 * @see    https://github.com/gwillem/magento-module-blacklist
 * @author Ryan Hoerr <rhoerr@gmail.com>
 * @author Jisse Reitsma <jisse@yireo.com>
 */

namespace ModuleBlacklist\Magerun2;

use ModuleBlacklist\Magerun2\Blacklist\Entry;

/**
 * Class Blacklist
 *
 * @package ModuleBlacklist\Magerun2
 */
class Blacklist
{
    /**
     * CSV list of vulnerable extensions
     */
    const BLACKLIST_URL = 'https://raw.githubusercontent.com/gwillem/magevulndb/master/magento2-vulnerable-extensions.csv';

    /**
     * @var Entry[]
     */
    private $entries = [];

    /**
     * @var ModuleVersion
     */
    private $moduleVersion;

    /**
     * Blacklist constructor.
     *
     * @param ModuleVersion $moduleVersion
     */
    public function __construct(
        ModuleVersion $moduleVersion
    ) {
        $this->moduleVersion = $moduleVersion;
    }

    /**
     * Check if this list has vulnerable extensions
     *
     * @return bool
     */
    public function hasEntries()
    {
        return (bool)$this->getEntries();
    }

    /**
     * Get a list of vulnerable extensions
     *
     * @return Entry[]
     */
    public function getEntries(): array
    {
        if (count($this->entries) > 0) {
            return $this->entries;
        }

        if (($handle = fopen(self::BLACKLIST_URL, "r")) !== false) {
            while (($data = fgetcsv($handle, 1000, ",")) !== false) {
                if ($data[0] === 'Name') {
                    continue;
                }

                $this->entries[] = new Entry(
                    (string)$data[0],
                    $this->moduleVersion->getModuleVersion((string)$data[0]),
                    (string)$data[1],
                    (string)$data[2],
                    $this->getFrontnameFromRoute((string)$data[2]),
                    (string)$data[3],
                    (string)$data[4]
                );
            }

            fclose($handle);
        }

        return $this->entries;
    }

    /**
     * Get the frontname from the given (assumed) Magento route URL.
     *
     * @param string $route
     * @return string
     */
    protected function getFrontnameFromRoute(string $route): string
    {
        // Strip off any leading index.php and slashes. A frontname shouldn't contain either.
        $route = str_replace('index.php', '', $route);
        $route = trim($route, '/?');

        // If this looks like a multi-part route, the frontname is the first part.
        if (strpos($route, '/') !== false) {
            $route = substr($route, 0, strpos($route, '/'));
        }

        return $route;
    }
}
