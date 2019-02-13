# Magento Vulnerability Database

List of Magento 1 integrations with known security issues. **Objective: easily identify insecure 3rd party software in your Magento code base.** See my blog for the rationale: [Bad extensions now main source of Magento hacks & a solution](https://gwillem.gitlab.io/2019/01/29/magento-module-blacklist/)

![n98-magerun dev:module:security](https://buq.eu/screenshots/kUOyTTWeDIUXUrGU1kqAmqu5.png)

# [The List](magento1-vulnerable-extensions.csv)

The list contains these columns:

1. Vendor_Name of the module (as reported by `n98-magerun dev:module:list` or `Mage::getConfig()->getNode()->modules`)
1. The earliest safe version to use. Older entries are considered insecure. 
1. Part of the URL that attackers use to exploit this module. Can be used to search logfiles for malicious activity. (optional)
1. Reference URL describing the problem. If no public statement is available, then the name of the researcher who discovered it.
1. URL with upgrade instructions (optional)

# Context

Magento is an attractive target for payment skimmers and the number of attacks has increased steadily since 2015. In 2018, attackers shifted from Magento core exploits (eg, Shoplift, brute force attacks on admin passwords) to [3rd party software components](https://gwillem.gitlab.io/2018/10/23/magecart-extension-0days/). This poses a practical problem: there is no central place where one can (programmatically) find out whether a particular module version has known security issues. This repository solves that!

# Usage

You can quickly scan your site against this repository using a Magerun module or a single-line command. Both require command line or SSH access to the server. Magerun is recommended as it can be easily scheduled or used on an ongoing basis, and provides better output. Both approaches load the latest vulnerability data on every run.

### Magerun module (recommended)

1. [Install n98-magerun](https://github.com/netz98/n98-magerun)
2. Install the Magento Vulnerability Database plugin:
```
mkdir -p ~/.n98-magerun/modules
cd ~/.n98-magerun/modules
git clone https://github.com/gwillem/magevulndb.git
```
3. Scan your Magento install:
```
n98-magerun.phar dev:module:security
```

You can also use the `-q` flag to limit output to findings only.
```
n98-magerun.phar dev:module:security -q
```

You can check the exit code, for example to fail a build when a vulnerable module is detected:

* exit code `0`: no known vulnerabilities found
* exit code `1`: known vulnerabilities found
* exit code `2`: vulnerability data could not be loaded

### No magerun installed?

To quickly check a Magento installation for vulnerable modules, run this command in SSH **at your Magento site root**:

    php -r "require_once('app/Mage.php');Mage::app();$config=Mage::getConfig()->getNode()->modules;$found=array();$list=fopen('https://raw.githubusercontent.com/gwillem/magevulndb/master/magento1-vulnerable-extensions.csv','r');while($list&&list($name,$version)=list($row['module'],$row['fixed_in'],,$row['reference'],$row['update'])=fgetcsv($list)){if(isset($name,$version,$config->{$name},$config->{$name}->version)&&(empty($version)||version_compare($config->{$name}->version,$version,'<'))){$found[]=$row;}}if($found){echo 'Found possible vulnerable modules: '.print_r($found,1);exit(1);}echo 'No known vulnerable modules detected.';exit(0);}"

You can check the exit code, for example to fail a build when a vulnerable module is detected:

* exit code `0`: no known vulnerabilities found
* exit code `1`: known vulnerabilities found

# Contributing

Contributions welcome. Requirements:

- Either "name" or "uri" (in case of exploitation in the wild) is required.
- A reputable, verifiable source is required.

Only security issues that have *verified proof* or are being *actively exploited* in the wild should be considered. 

# FAQ

### Why a new repository?

There are many good initiatives already, however they either lack a simple web GUI, are too complicated to maintain or do not cover all extensions out there. For Magento 2, there is already excellent support via composer, please refer to [Roave's SecurityAdvisories](https://github.com/Roave/SecurityAdvisories) for automated composer integration.

### What if a module has multiple security issues over time?

We register the newest only and advice everybody to upgrade to the latest version. If people want to stick to an older (possible insecure) version, they should study the relevant changelogs. 

### What about modules that are known under several names?

The name as registered in the code (and output by `n98-magerun dev:module:list`) is leading. If a module is known under several (code) names, then we should create duplicate entries, so that automated tools will not ignore such an entry.

### There are multiple sources, which should I use?

If the vendor has issued a security statement, that should be leading. Otherwise, a statement by a security researcher (Blog/Twitter) can be used. If a vendor has issued a statement that is false or misleading, an independent statement should take precedence. 

### We could add more information X?

Indeed, but the main advantage of a simple CSV with few columns is that it's easy to browse, maintain and extend. Other projects have stalled because there is too much overhead in vulnerability administration. The primary objective of this repository is to support a n98-magerun command. If people want more information, they can look it up via the referenced source. 

### What is the URL column for?

This can be used by tools to filter "suspicious" web traffic from the logs. Ie, check if malicious activity has already taken place. 

### What if there are multiple relevant URLs?

Seperate them with a ";"

### What if a module does not have version numbers?

Use the date of the fix in YYYY-MM-DD notation.

# Acknowledgements

These Magento/security professionals have contributed valuable research and code:

- Ryan Hoerr - ParadoxLabs
- Peter O'Callaghan
- Max Chadwick - Something Digital
- Jeroen Vermeulen - MageHost.pro
- Roland Walraven - MageHost.pro
- Martin Pachol - MageMojo

# License

The information and code of this repository is provided free of charge, without warranty or assumed liability of any kind. Merchants and development agencies are free to use this data to assess their own stores. It is not allowed to use or include this data in commercial products or offerings. 

# Contact

[gwillem@gmail.com](mailto:gwillem@gmail.com?subject=magevulndb)
