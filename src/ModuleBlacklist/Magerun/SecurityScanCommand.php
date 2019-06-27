<?php
/**
 * Magerun plugin: Scan the current Magento 1 installation for known vulnerable modules.
 *
 * Execute as:
 *  n98-magerun.phar dev:module:security [-q]
 *
 * @see    https://github.com/gwillem/magento-module-blacklist
 * @author Ryan Hoerr <rhoerr@gmail.com>
 */

namespace ModuleBlacklist\Magerun;

use N98\Magento\Command\AbstractMagentoCommand;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

class SecurityScanCommand extends AbstractMagentoCommand
{
    const BLACKLIST_URL = 'https://raw.githubusercontent.com/gwillem/magevulndb/master/magento1-vulnerable-extensions.csv';

    /**
     * @var array
     */
    private $routeMap;

    /**
     * @return void
     */
    protected function configure()
    {
        $this->setName('dev:module:security')
             ->setDescription('Check installed modules for known vulnerabilities');
    }

    /**
     * Check the current Magento install for any modules matching MageVulnDb.
     *
     * @param \Symfony\Component\Console\Input\InputInterface $input
     * @param \Symfony\Component\Console\Output\OutputInterface $output
     * @return int exit code: 0 no known vulnerabilities found, 1 vulnerabilities found, 2 data could not be loaded
     */
    protected function execute(InputInterface $input, OutputInterface $output)
    {
        $this->detectMagento($output);

        if ($this->initMagento()) {
            $blacklist = fopen(static::BLACKLIST_URL, 'rb');
            $hitCount  = 0;

            if ($blacklist === false) {
                $output->writeln(
                    '<error>Unable to load the latest vulnerability data.</error>',
                    OutputInterface::VERBOSITY_QUIET
                );

                return 2;
            }

            while ($row = $this->getRowObject(fgetcsv($blacklist))) {
                if ($this->checkIsInstalledModule($output, $row)) {
                    $hitCount++;
                } else {
                    $this->checkIsInstalledRoute($output, $row);
                }
            }

            if ($hitCount === 0) {
                $output->writeln('No known vulnerable modules detected.');
                return 0;
            }

            return 1;
        }

        return 2;
    }

    /**
     * Check row for match in installed modules, by version
     *
     * @param \Symfony\Component\Console\Output\OutputInterface $output
     * @param \Varien_Object $row
     * @return bool
     */
    protected function checkIsInstalledModule(OutputInterface $output, \Varien_Object $row)
    {
        // No match if module has no installed version, or version is equal/greater than fixed-in.
        if ($row->getVersion() === null
            || (!empty($row->getFixedIn()) && version_compare($row->getVersion(), $row->getFixedIn(), '>='))) {
            return false;
        }

        $output->writeln(
            sprintf(
                '<error>Vulnerable module found: %s%s</error>',
                $row->getName(),
                $output->isQuiet() && !empty($row->getFixedIn())
                    ? sprintf(' (%s < %s)', $row->getVersion(), $row->getFixedIn())
                    : ''
            ),
            OutputInterface::VERBOSITY_QUIET
        );

        $output->writeln(sprintf('<comment>Installed:</comment>  %s', $row->getVersion()));
        $output->writeln(sprintf('<comment>Fixed In:</comment>   %s', $row->getFixedIn() ?: '(unknown)'));

        if (!empty($row->getUpdateUrl())) {
            $output->writeln(sprintf('<comment>Update URL:</comment> %s', $row->getUpdateUrl()));
        }

        if (!empty($row->getCredit())) {
            $output->writeln(sprintf('<comment>Credit:</comment>     %s', $row->getCredit()));
        }

        $output->writeln('');

        return true;
    }

    /**
     * Check for match in frontend routes if module is unknown
     *
     * @param \Symfony\Component\Console\Output\OutputInterface $output
     * @param \Varien_Object $row
     * @return bool
     */
    protected function checkIsInstalledRoute(OutputInterface $output, \Varien_Object $row)
    {
        $module = $this->getModuleByRoute($row->getFrontname());

        // No match if there's no module matching the frontname, or if we know what module it is for.
        // Those will match by module name, if they're related.
        if ($module === null || ($row->getName() !== '?' && !empty($row->getName()))) {
            return false;
        }

        $output->writeln(
            sprintf(
                '<comment>Potential vulnerable module found: %s%s</comment>',
                $module,
                $output->isQuiet() ? sprintf(' (route match: %s)', $row->getFrontname()) : ''
            ),
            OutputInterface::VERBOSITY_QUIET
        );

        $output->writeln(
            '<info>'
            . 'Matched by route: This may be a false positive where your installed module' . "\n"
            . 'shares it with a vulnerable module, but it should be investigated further.' . "\n"
            . 'Please contribute info about the module to MageVulnDb if it is relevant.'
            . '</info>'
        );

        $output->writeln(sprintf('<comment>Route:</comment>      %s', $row->getFrontname()));
        $output->writeln(sprintf('<comment>Looks Like:</comment> %s', $row->getRoute()));
        $output->writeln(sprintf('<comment>Module:</comment>     %s', $module));
        $output->writeln(sprintf('<comment>Installed:</comment>  %s', $this->getModuleVersion($module)));

        if (!empty($row->getUpdateUrl())) {
            $output->writeln(sprintf('<comment>Update URL:</comment> %s', $row->getUpdateUrl()));
        }

        if (!empty($row->getCredit())) {
            $output->writeln(sprintf('<comment>Credit:</comment>     %s', $row->getCredit()));
        }

        $output->writeln('');

        return true;
    }

    /**
     * Get the module tag of the installed module matching the given route (if any).
     *
     * @param string $frontName
     * @return string|null
     */
    protected function getModuleByRoute($frontName)
    {
        if ($this->routeMap === null) {
            $routers = \Mage::getConfig()->getNode()->frontend->routers->asArray();
            $this->routeMap = array();
            foreach ($routers as $router) {
                if (isset($router['args']['frontName'], $router['args']['module'])) {
                    $this->routeMap[strtolower($router['args']['frontName'])] = $router['args']['module'];
                }
            }
        }

        $frontName = strtolower($frontName);

        return isset($this->routeMap[$frontName])
            ? $this->routeMap[$frontName]
            : null;
    }

    /**
     * Get the installed version of the given module tag (if any).
     *
     * @param string $moduleTag
     * @return \SimpleXMLElement|null
     */
    protected function getModuleVersion($moduleTag)
    {
        return isset(\Mage::getConfig()->getNode()->modules->{$moduleTag}->version)
            ? \Mage::getConfig()->getNode()->modules->{$moduleTag}->version
            : null;
    }

    /**
     * Get the frontname from the given (assumed) Magento route URL.
     *
     * @param string $route
     * @return string
     */
    protected function getFrontname($route)
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

    /**
     * Turn a MageVulnDb M1 CSV row into a keyed Varien_Object.
     *
     * @param array $csvRow
     * @return \Varien_Object|false
     */
    protected function getRowObject($csvRow)
    {
        if (!is_array($csvRow)) {
            return false;
        }

        return new \Varien_Object(array(
            'name'       => $csvRow[0],
            'version'    => $this->getModuleVersion($csvRow[0]),
            'fixed_in'   => $csvRow[1],
            'route'      => $csvRow[2],
            'frontname'  => $this->getFrontname($csvRow[2]),
            'credit'     => $csvRow[3],
            'update_url' => $csvRow[4],
        ));
    }
}
