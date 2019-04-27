<?php
/**
 * Magerun2 plugin: Scan the current Magento 2 installation for known vulnerable modules.
 *
 * @see    https://github.com/gwillem/magento-module-blacklist
 * @author Ryan Hoerr <rhoerr@gmail.com>
 * @author Jisse Reitsma <jisse@yireo.com>
 */

namespace ModuleBlacklist\Magerun2;

use Magento\Framework\Component\ComponentRegistrar;
use Magento\Framework\Module\ModuleListInterface;

/**
 * Class ModuleVersion
 *
 * @package ModuleBlacklist\Magerun2
 */
class ModuleVersion
{
    /**
     * @var ModuleListInterface
     */
    private $moduleList;

    /**
     * @var ComponentRegistrar
     */
    private $componentRegistrar;

    /**
     * Blacklist constructor.
     *
     * @param ModuleListInterface $moduleList
     * @param ComponentRegistrar $componentRegistrar
     */
    public function __construct(
        ModuleListInterface $moduleList,
        ComponentRegistrar $componentRegistrar
    ) {
        $this->moduleList = $moduleList;
        $this->componentRegistrar = $componentRegistrar;
    }

    /**
     * Get the installed version of the given module tag (if any).
     *
     * @param string $moduleName
     * @return string
     */
    public function getModuleVersion(string $moduleName): string
    {
        if ($version = $this->loadVersionFromComposer($moduleName)) {
            return $version;
        }

        return $this->loadVersionFromModuleXml($moduleName);
    }

    /**
     * @param string $moduleName
     * @return string
     */
    protected function loadVersionFromComposer(string $moduleName): string
    {
        $modulePath = $this->componentRegistrar->getPath('module', $moduleName);
        if (empty($modulePath)) {
            return '';
        }

        $composerFile = $modulePath . '/composer.json';
        if (!file_exists($composerFile) || !is_readable($composerFile)) {
            return '';
        }

        $composerContent = file_get_contents($composerFile);
        if (empty($composerContent)) {
            return '';
        }

        $composerData = json_decode($composerContent, true);
        if (!isset($composerData['version'])) {
            return '';
        }

        return (string)$composerData['version'];
    }

    /**
     * @param string $moduleName
     * @return string
     */
    protected function loadVersionFromModuleXml(string $moduleName): string
    {
        $module = $this->moduleList->getOne($moduleName);
        if (isset($module['setup_version'])) {
            return $module['setup_version'];
        }

        return '';
    }
}
