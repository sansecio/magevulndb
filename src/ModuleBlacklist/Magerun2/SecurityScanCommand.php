<?php
/**
 * Magerun plugin: Scan the current Magento 2 installation for known vulnerable modules.
 *
 * Execute as:
 *  n98-magerun2.phar dev:module:security [-q]
 *
 * @see    https://github.com/gwillem/magento-module-blacklist
 * @author Ryan Hoerr <rhoerr@gmail.com>
 * @author Jisse Reitsma <jisse@yireo.com>
 */

namespace ModuleBlacklist\Magerun2;

use Exception;
use Magento\Framework\App\Config\ScopeConfigInterface;
use Magento\Framework\App\ObjectManager;
use Magento\Framework\App\Route\ConfigInterface;
use Magento\Framework\App\RouterList;
use Magento\Framework\App\RouterListInterface;
use Magento\Framework\App\State;
use Magento\Framework\Exception\LocalizedException;
use Magento\Framework\Module\ModuleListInterface;
use ModuleBlacklist\Magerun2\Blacklist\Entry;
use N98\Magento\Command\AbstractMagentoCommand;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * Magerun2 command for scanning for modules with known security issues
 */
class SecurityScanCommand extends AbstractMagentoCommand
{
    /**
     * @var array
     */
    private $routeMap;

    /**
     * @var Blacklist
     */
    private $blacklist;

    /**
     * @var ModuleListInterface
     */
    private $moduleList;

    /**
     * @var ModuleVersion
     */
    private $moduleVersion;

    /**
     * @return void
     */
    protected function initDependencies()
    {
        $objectManager = ObjectManager::getInstance();
        $this->blacklist = $objectManager->get(Blacklist::class);
        $this->moduleList = $objectManager->get(ModuleListInterface::class);
        $this->moduleVersion = $objectManager->get(ModuleVersion::class);
    }

    /**
     * @return void
     */
    protected function configure()
    {
        $this
            ->setName('dev:module:security')
            ->setDescription('Check installed modules for known vulnerabilities');
    }

    /**
     * Check the current Magento install for any modules matching MageVulnDb.
     *
     * @param InputInterface $input
     * @param OutputInterface $output
     * @return int exit code: 0 no known vulnerabilities found, 1 vulnerabilities found, 2 data could not be loaded
     * @throws Exception
     */
    protected function execute(InputInterface $input, OutputInterface $output)
    {
        $this->detectMagento($output);

        if (!$this->initMagento()) {
            return 2;
        }   

        $this->initDependencies();

        $hitCount = 0;

        if ($this->blacklist->hasEntries() === false) {
            $output->writeln(
                '<error>Unable to load the latest vulnerability data.</error>',
                OutputInterface::VERBOSITY_QUIET
            );

            return 2;
        }

        foreach ($this->blacklist->getEntries() as $entry) {
            if ($this->reportVulnerableModule($output, $entry)) {
                $hitCount++;
            } else {
                $this->reportVulnerableRoute($output, $entry);
            }
        }

        if ($hitCount === 0) {
            $output->writeln('No known vulnerable modules detected.');
            return 0;
        }

        return 1;
    }

    /**
     * Check row for match in installed modules, by version
     *
     * @param OutputInterface $output
     * @param Entry $entry
     * @return bool
     */
    protected function reportVulnerableModule(OutputInterface $output, Entry $entry)
    {
        if (!$entry->isModuleVulnerable()) {
            return false;
        }

        $output->writeln(
            sprintf(
                '<error>Vulnerable module found: %s%s</error>',
                $entry->getModuleName(),
                $output->isQuiet() && !empty($entry->getFixedIn())
                    ? sprintf(' (%s < %s)', $entry->getCurrentVersion(), $entry->getFixedIn())
                    : ''
            ),
            OutputInterface::VERBOSITY_QUIET
        );

        $output->writeln(sprintf('<comment>Installed:</comment>  %s', $entry->getCurrentVersion()));
        $output->writeln(sprintf('<comment>Fixed In:</comment>   %s', $entry->getFixedIn() ?: '(unknown)'));

        if (!empty($entry->getUpdateUrl())) {
            $output->writeln(sprintf('<comment>Update URL:</comment> %s', $entry->getUpdateUrl()));
        }

        if (!empty($entry->getCredit())) {
            $output->writeln(sprintf('<comment>Credit:</comment>     %s', $entry->getCredit()));
        }

        $output->writeln('');

        return true;
    }

    /**
     * Check for match in frontend routes if module is unknown
     *
     * @param OutputInterface $output
     * @param Entry $row
     * @return bool
     */
    protected function reportVulnerableRoute(OutputInterface $output, Entry $entry)
    {
        $module = $this->getModuleByRoute($entry->getFrontname());

        // No match if there's no module matching the frontname
        if (empty($module)) {
            return false;
        }

        // No match if we know what module it is for
        // Those will match by module name, if they're related.
        if ($entry->getModuleName() !== '?' && !empty($entry->getModuleName())) {
            return false;
        }

        $output->writeln(
            sprintf(
                '<comment>Potential vulnerable module found: %s%s</comment>',
                $module,
                $output->isQuiet() ? sprintf(' (route match: %s)', $entry->getFrontname()) : ''
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

        $output->writeln(sprintf('<comment>Route:</comment>      %s', $entry->getFrontname()));
        $output->writeln(sprintf('<comment>Looks Like:</comment> %s', $entry->getRoute()));
        $output->writeln(sprintf('<comment>Module:</comment>     %s', $module));
        $output->writeln(sprintf('<comment>Installed:</comment>  %s', $this->moduleVersion->getModuleVersion($module)));

        if (!empty($entry->getUpdateUrl())) {
            $output->writeln(sprintf('<comment>Update URL:</comment> %s', $entry->getUpdateUrl()));
        }

        if (!empty($entry->getCredit())) {
            $output->writeln(sprintf('<comment>Credit:</comment>     %s', $entry->getCredit()));
        }

        $output->writeln('');

        return true;
    }

    /**
     * Get the module tag of the installed module matching the given route (if any).
     *
     * @param string $frontName
     * @return string
     */
    protected function getModuleByRoute(string $frontName): string
    {
        $objectManager = ObjectManager::getInstance();

        /** @var State $state */
        $state = $objectManager->get(State::class);

        try {
            $state->setAreaCode('frontend');
        } catch (LocalizedException $e) {
        }

        /** @var ConfigInterface $routeConfig */
        $routeConfig = $objectManager->get(ConfigInterface::class);
        $modules = $routeConfig->getModulesByFrontName($frontName);

        if (empty($modules)) {
            return '';
        }

        // @todo: We actually can have a list of possible modules
        return $modules[0];
    }
}
