<?php
/**
 * Magerun plugin: Scan the current Magento 1 installation for known vulnerable modules.
 *
 * Execute as:
 *  n98-magerun.phar dev:module:security [-q]
 *
 * @see    https://github.com/gwillem/magento1-module-blacklist
 * @author Ryan Hoerr <rhoerr@gmail.com>
 */

namespace ModuleBlacklist\Magerun;

use N98\Magento\Command\AbstractMagentoCommand;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

class SecurityScanCommand extends AbstractMagentoCommand
{
    const BLACKLIST_URL = 'https://raw.githubusercontent.com/gwillem/magento1-module-blacklist/master/magento1-vulnerable-extensions.csv';
    
    /**
     * @return void
     */
    protected function configure()
    {
        $this->setName('dev:module:security')
             ->setDescription('Check installed modules for known vulnerabilities');
    }

   /**
    * @param \Symfony\Component\Console\Input\InputInterface $input
    * @param \Symfony\Component\Console\Output\OutputInterface $output
    * @return void
    */
    protected function execute(InputInterface $input, OutputInterface $output)
    {
        $this->detectMagento($output);
        
        if ($this->initMagento()) {
            $modules   = \Mage::getConfig()->getNode()->modules;
            $blacklist = fopen(static::BLACKLIST_URL, 'r');
            $hitCount  = 0;
            
            if ($blacklist === false) {
                $output->writeln(
                    '<error>Unable to load the latest vulnerability data.</error>',
                    OutputInterface::VERBOSITY_QUIET
                );
                return;
            }
            
            while ($row = fgetcsv($blacklist)) {
                $name      = $row[0];
                $fixedIn   = $row[1];
                $credit    = $row[3];
                $updateUrl = $row[4];
                $version   = isset($modules->{$name}->version) ? $modules->{$name}->version : null;
                
                if ($version !== null
                    && (empty($fixedIn) || version_compare($modules->{$name}->version, $fixedIn, '<'))) {
                    $output->writeln(
                        sprintf(
                            '<error>Vulnerable module found: %s%s</error>',
                            $name,
                            $output->isQuiet() && !empty($fixedIn) ? sprintf(' (%s < %s)', $version, $fixedIn) : ''
                        ),
                        OutputInterface::VERBOSITY_QUIET
                    );
                    
                    $output->writeln(sprintf('<comment>Installed:</comment>  %s', $modules->{$name}->version));
                    $output->writeln(sprintf('<comment>Fixed In:</comment>   %s', $fixedIn ?: '(none)'));
                    
                    if (!empty($updateUrl)) {
                        $output->writeln(sprintf('<comment>Update URL:</comment> %s', $updateUrl));
                    }
                    
                    if (!empty($credit)) {
                        $output->writeln(sprintf('<comment>Credit:</comment>     %s', $credit));
                    }
                    
                    $output->writeln('');
                    
                    $hitCount++;
                }
            }

            if ($hitCount === 0) {
                $output->writeln('No known vulnerable modules detected.');
            }
        }
    }
}
