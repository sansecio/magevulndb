![](https://buq.eu/stuff/blacklist.png)

# Magento1 Module Blacklist

List of Magento 1 integrations with known security issues. Looking for [Magento 2](https://github.com/Roave/SecurityAdvisories)?

Objectives:
1. Easily identify insecure 3rd party software in your code base. 
1. Run `n98-magerun dev:module:security` to see insecure installed modules. 

Intended audience: developers, administrators, security auditors

# [The List](magento1-vulnerable-extensions.csv)

# Context

Magento is an attractive target for payment skimmers and the number of attacks has increased steadily since 2015. In 2018, attackers are shifting from Magento core exploits (eg, Shoplift, brute force attacks on admin passwords) to [3rd party software components](https://gwillem.gitlab.io/2018/10/23/magecart-extension-0days/). This poses a practical problem: there is no central place where one can (programmatically) find out whether a particular module version has known security issues. This repository solves that!

# Todo

- [ ] Import past security incidents
- [ ] Release n98-magerun module that checks for insecure modules, similar to the module version checker @ http://tools.hypernode.com/
- [ ] Integrate with Ext-DN

# Contributing

Contributions welcome. Requirements:

- Either "name" or "uri" (in case of exploitation in the wild) is required.
- A verifiable source is required.

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

# Contributors:

- Peter O'Callaghan
- Max Chadwick
- Ryan Hoerr
- Jeroen Vermeulen
- Willem de Groot
