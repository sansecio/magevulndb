# Magento Vulnerability Database

List of Magento 1 and 2 integrations with known security issues. **Objective: easily identify insecure 3rd party software in your Magento code base.** See our blog for the rationale: [Bad extensions now main source of Magento hacks & a solution](https://sansec.io/research/magento-module-blacklist)

![n98-magerun dev:module:security](https://buq.eu/screenshots/kUOyTTWeDIUXUrGU1kqAmqu5.png)

# Data

Each vulnerable module has one YAML file: [`m1/`](m1) for Magento 1, [`m2/`](m2) for Magento 2. The file name is the module name as registered in code (`n98-magerun dev:module:list` under M1, `bin/magento module:status` under M2).

```yaml
# m2/StripeIntegration_Payments.yaml
module: StripeIntegration_Payments
composer:                                 # optional, every package name the module ships under
  - stripe/stripe-payments
update_url: https://github.com/stripe/stripe-magento2-releases   # optional
advisories:
  - id: MVD-2025-0012                     # stable, never reused
    title: Unauthenticated webhook access
    published: 2025-04-11
    cve: CVE-2025-12345                   # optional
    cvss: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"   # optional, full 3.1 or 4.0 vector
    known_exploited: true                 # optional
    uri:                                  # optional, request paths that hit the vulnerable code
      - /stripe/webhooks
    reference: https://github.com/stripe/stripe-magento2-releases/blob/master/CHANGELOG.md
    affected: ">=4.0,<4.4.2 || <3.5.9"
```

`affected` is a [composer version constraint](https://getcomposer.org/doc/articles/versions.md#writing-version-constraints): `,` means AND, `||` means OR. A module without a fix gets `"*"`. Match installed versions with `composer/semver`: `Semver::satisfies($installed, $affected)`.

Other optional fields: `abandoned: true` when the vendor no longer maintains the module, `version_scheme: nonstandard` when the installed version does not match vendor release numbers (scanners then match by name only), `notes`, and `credit` (per advisory) for a researcher when there is no reference URL. [`schema/module.schema.json`](schema/module.schema.json) has the full format. Vulnerable URLs whose module is unknown are in [`m1/_unknown.yaml`](m1/_unknown.yaml).

The CSV files [`magento1-vulnerable-extensions.csv`](magento1-vulnerable-extensions.csv) and [`magento2-vulnerable-extensions.csv`](magento2-vulnerable-extensions.csv) are DEPRECATED. They stay at their current paths for installed magerun modules, but get no new entries.

# Context

Magento is an attractive target for payment skimmers and the number of attacks has increased steadily since 2015. In 2018, attackers shifted from Magento core exploits (eg, Shoplift, brute force attacks on admin passwords) to [3rd party software components](https://gwillem.gitlab.io/2018/10/23/magecart-extension-0days/). This poses a practical problem: there is no central place where one can (programmatically) find out whether a particular module version has known security issues. This repository solves that!

# Usage

You can quickly scan your site against this repository using a Magerun module or a single-line command. Both require command line or SSH access to the server. Magerun is recommended as it can be easily scheduled or used on an ongoing basis, and provides better output. Both approaches load the latest vulnerability data on every run.

### Magerun module (recommended)

1. [Install n98-magerun](https://github.com/netz98/n98-magerun) for Magento 1 or Magento 2.
2. Install the Magento Vulnerability Database plugin:
For Magento 1:
```
mkdir -p ~/.n98-magerun/modules
cd ~/.n98-magerun/modules
git clone https://github.com/gwillem/magevulndb.git
```
For Magento 2:
```
mkdir -p ~/.n98-magerun2/modules
cd ~/.n98-magerun2/modules
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

### JSON feed

Every merge to `main` publishes all M1 and M2 modules as one JSON file:

    https://github.com/sansecio/magevulndb/releases/download/latest/magevulndb.json

It has the same fields as the YAML files, plus `severity` (low, medium, high, critical) derived from `cvss`.

### Composer

Every merge to `main` also publishes an advisory-only composer repository. Add it to your project's `composer.json`:

```json
"repositories": [{"type": "composer", "url": "https://sansecio.github.io/magevulndb"}]
```

`composer audit` then reports vulnerable extensions, including those installed from vendor or Marketplace repositories. Composer 2.9 and later also refuse to install vulnerable versions during `composer update`. To silence one advisory, add its id to `audit.ignore`. This only covers modules with a `composer` name in their YAML file.

### No magerun installed under Magento 1?

To quickly check a Magento installation for vulnerable modules, run this command in SSH **at your Magento 1 site root**:

    php -r 'require_once("app/Mage.php");Mage::app();$config=Mage::getConfig()->getNode()->modules;$found=array();$list=fopen("https://raw.githubusercontent.com/sansecio/magevulndb/main/magento1-vulnerable-extensions.csv","r");while($list&&list($name,$version)=list($row["module"],$row["fixed_in"],,$row["reference"],$row["update"])=fgetcsv($list)){if(isset($name,$version,$config->{$name},$config->{$name}->version)&&(empty($version)||version_compare($config->{$name}->version,$version,"<"))){$found[]=$row;}}if($found){echo "Found possible vulnerable modules: ".print_r($found,1);}else{echo "No known vulnerable modules detected.";}'

You can check the exit code, for example to fail a build when a vulnerable module is detected:

* exit code `0`: no known vulnerabilities found
* exit code `1`: known vulnerabilities found

This script only works under Magento 1 and reads the frozen M1 CSV. For Magento 2, use Magerun instead.

# Contributing

Contributions welcome. Add or edit the module's YAML file in `m1/` or `m2/`. For a new advisory, take the next free `MVD-<year>-<number>` id. CI checks every pull request against the schema, parses `affected` as a composer constraint and scores `cvss`. To run the same checks locally:

```
composer install
bin/validate
```

Requirements:

- Either a module name or a `uri` (in case of exploitation in the wild) is required.
- `affected` must match the vendor changelog. Composer blocks updates to versions in that range, so a wrong range stops merchants' `composer update`.
- A reputable, verifiable source is required.
- In case of admin URL disclosure: the issue is not fixed by disabling the [security compatibility mode](https://magento.stackexchange.com/questions/88435/admin-routing-compatibility-mode-for-extensions-enable-or-disable)

Only security issues that have *verified proof* or are being *actively exploited* in the wild should be considered. 

Please consider *responsible disclosure* before submitting zero-day vulnerabilities. If no immediate abuse is likely, please notify the vendor first and allow 30 days for a patch & release statement. 

# FAQ

### Why a new repository?

There are many good initiatives already, however they either lack a simple web GUI, are too complicated to maintain or do not cover all extensions out there. For Magento 2, there is already excellent support via composer, please refer to [Roave's SecurityAdvisories](https://github.com/Roave/SecurityAdvisories) for automated composer integration. Still, Roave's approach requires you to run a composer command to check for new updates. With this Magerun command, you can leave the composer files untouched. Obviously, it also works on Magento 1 and 2 installs that are not managed by composer at all.

### What if a module has multiple security issues over time?

Add one advisory per issue to the module's file. Entries converted from the old CSV have a single advisory that covers all versions before the newest fix.

### What about modules that are known under several names?

The name as registered in the code (and output by `n98-magerun dev:module:list`) is leading. If a module is known under several (code) names, then we should create duplicate entries, so that automated tools will not ignore such an entry.

### What if I don't know the module name?

If you have a URL that is being attacked but don't know what module it belongs to, submit it but leave the name "`?`". It will be backfilled when the actual module is identified.

### There are multiple sources, which should I use?

If the vendor has issued a security statement, that should be leading. Otherwise, a statement by a security researcher (Blog/Twitter) can be used. If a vendor has issued a statement that is false or misleading, an independent statement should take precedence. 

### We could add more information X?

Only the fields in the schema are required or allowed. Other projects have stalled because there is too much overhead in vulnerability administration, so most fields are optional. For anything else, people can read the referenced source.

### What is the `uri` field for?

This can be used by tools to filter "suspicious" web traffic from the logs, for example to check if malicious activity has already taken place. The URI should be enough to uniquely match the module's vulnerable URL(s), if possible.    

### What if there are multiple relevant URLs?

List each one under `uri`.

### What if a module does not have version numbers?

Use the date of the fix in YYYY-MM-DD notation, for example `affected: "<2023-09-03"`.

### What if the vendor provides a fix but does not update the version number?

Some Magento 1 modules, such as Mirasvit ([discussion](https://github.com/gwillem/magevulndb/pull/40)), report a version in `config.xml` that does not match the vendor's release numbers. These files have `version_scheme: nonstandard`, so scanners match by name and skip the version comparison. The old CSV prefixed such modules with an underscore.

# Acknowledgements

These Magento/security professionals have contributed valuable research and code:

- Ryan Hoerr - ParadoxLabs
- Peter O'Callaghan
- Max Chadwick - Something Digital
- Jeroen Vermeulen - MageHost.pro
- Roland Walraven - MageHost.pro
- Martin Pachol - MageMojo
- Jisse Reitsma - Yireo
- [Niko Granö](https://xn--gran-8qa.fi) - [Lamia.fi](https://lamia.fi/en/)
- Martien Mortiaux - [AlterWeb.nl](https://www.alterweb.nl/)

# License

The information and code of this repository is provided free of charge, without warranty or assumed liability of any kind. Merchants and development agencies are free to use this data to assess their own stores. It is not allowed to use or include this data in commercial products or offerings. 

# Contact

[info@sansec.io](mailto:info@sansec.io?subject=magevulndb)
