<?php

declare(strict_types=1);

namespace MageVulnDb;

/** Builds the published artifacts from validated module files. */
final class Builder
{
    public const int FORMAT = 1;

    /**
     * Builds magevulndb.json: all modules per platform, sorted by name, with severity derived from cvss.
     *
     * @param array<string, array<string, mixed>> $files validated data keyed by path
     */
    public function json(array $files, \DateTimeImmutable $now): array
    {
        $out = ['format' => self::FORMAT, 'generated_at' => $now->setTimezone(new \DateTimeZone('UTC'))->format('Y-m-d\TH:i:s\Z')];
        foreach (Loader::DIRS as $platform) {
            $out[$platform] = [];
        }
        foreach ($files as $path => $module) {
            foreach ($module['advisories'] as &$adv) {
                if (isset($adv['cvss'])) {
                    $adv['severity'] = Cvss::severity($adv['cvss']);
                }
            }
            unset($adv);
            $out[strtok($path, '/')][] = $module;
        }
        foreach (Loader::DIRS as $platform) {
            usort($out[$platform], fn (array $a, array $b): int => strcmp($a['module'], $b['module']));
        }

        return $out;
    }

    /**
     * Builds an advisory-only composer repository: packages.json plus one p2/<vendor>/<package>.json per composer name.
     *
     * @param array<string, array<string, mixed>> $files   validated data keyed by path
     * @param string                              $baseUrl absolute URL the repository is served from; composer
     *                                                     resolves a leading-slash metadata-url against the host only
     *
     * @return array<string, array<string, mixed>> file contents keyed by relative output path
     */
    public function composerRepository(array $files, string $baseUrl): array
    {
        $byPackage = [];
        foreach ($files as $module) {
            foreach ($module['composer'] ?? [] as $name) {
                foreach ($module['advisories'] as $adv) {
                    $byPackage[$name][] = [
                        'advisoryId' => $adv['id'],
                        'packageName' => $name,
                        'title' => $adv['title'],
                        'affectedVersions' => $adv['affected'],
                        'sources' => [['name' => 'MageVulnDB', 'remoteId' => $adv['id']]],
                        'reportedAt' => $adv['published'] . ' 00:00:00',
                        'cve' => $adv['cve'] ?? null,
                        'link' => $adv['reference'] ?? null,
                        'severity' => isset($adv['cvss']) ? Cvss::severity($adv['cvss']) : null,
                    ];
                }
            }
        }
        ksort($byPackage, SORT_STRING);

        $out = ['packages.json' => [
            'packages' => [],
            'metadata-url' => rtrim($baseUrl, '/') . '/p2/%package%.json',
            'available-packages' => array_keys($byPackage),
            'security-advisories' => ['metadata' => true],
        ]];
        foreach ($byPackage as $name => $advisories) {
            $out["p2/$name.json"] = ['security-advisories' => $advisories];
        }

        return $out;
    }
}
