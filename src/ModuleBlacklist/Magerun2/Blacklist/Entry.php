<?php
/**
 * Magerun2 plugin: Scan the current Magento 2 installation for known vulnerable modules.
 *
 * @see    https://github.com/gwillem/magento-module-blacklist
 * @author Ryan Hoerr <rhoerr@gmail.com>
 * @author Jisse Reitsma <jisse@yireo.com>
 */

namespace ModuleBlacklist\Magerun2\Blacklist;

/**
 * Class Entry
 *
 * @package ModuleBlacklist\Magerun2\Blacklist
 */
class Entry
{
    /**
     * @var string
     */
    private $moduleName = '';

    /**
     * @var string
     */
    private $currentVersion = '';

    /**
     * @var string
     */
    private $fixedIn = '';

    /**
     * @var string
     */
    private $route = '';

    /**
     * @var string
     */
    private $frontName = '';

    /**
     * @var string
     */
    private $credit = '';

    /**
     * @var string
     */
    private $updateUrl = '';

    /**
     * Entry constructor.
     * @param string $moduleName
     * @param string $currentVersion
     * @param string $fixedIn
     * @param string $route
     * @param string $frontName
     * @param string $credit
     * @param string $updateUrl
     */
    public function __construct(
        string $moduleName,
        string $currentVersion,
        string $fixedIn,
        string $route,
        string $frontName,
        string $credit,
        string $updateUrl
    ) {
        $this->moduleName = $moduleName;
        $this->currentVersion = $currentVersion;
        $this->fixedIn = $fixedIn;
        $this->route = $route;
        $this->frontName = $frontName;
        $this->credit = $credit;
        $this->updateUrl = $updateUrl;
    }

    /**
     * @return bool
     */
    public function isModuleDetected(): bool
    {
        $version = $this->getCurrentVersion();
        return (bool)(!empty($version));
    }

    /**
     * @return bool
     */
    public function isModuleVulnerable(): bool
    {
        if (!$this->isModuleDetected()) {
            return false;
        }

        if (!$this->getFixedIn()) {
            return true;
        }

        if (version_compare($this->getCurrentVersion(), $this->getFixedIn(), '>=')) {
            return false;
        }

        return true;
    }

    /**
     * @return string
     */
    public function getModuleName(): string
    {
        return $this->moduleName;
    }

    /**
     * @return string
     */
    public function getCurrentVersion(): string
    {
        return $this->currentVersion;
    }

    /**
     * @return string
     */
    public function getFixedIn(): string
    {
        return $this->fixedIn;
    }

    /**
     * @return string
     */
    public function getRoute(): string
    {
        return $this->route;
    }

    /**
     * @return string
     */
    public function getFrontName(): string
    {
        return $this->frontName;
    }

    /**
     * @return string
     */
    public function getCredit(): string
    {
        return $this->credit;
    }

    /**
     * @return string
     */
    public function getUpdateUrl(): string
    {
        return $this->updateUrl;
    }
}
