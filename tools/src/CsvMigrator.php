<?php

declare(strict_types=1);

namespace MageVulnDb;

/** One-off conversion of the legacy CSVs to module YAML files. */
final class CsvMigrator
{
    /** Key that identifies a CSV row across history: the name without _ prefix or ? suffix, or the URI for unidentified ('?') rows. */
    public static function rowKey(string $platform, string $name, string $uri): string
    {
        return $name === '?' ? "$platform|?|$uri" : $platform . '|' . ltrim(rtrim($name, '?'), '_');
    }

    /**
     * Converts CSV rows into module files.
     *
     * @param list<array{0: string, 1: int, 2: string, 3: string, 4: string, 5: string, 6: string}> $rows
     *        [platform, line, Name, Fixed in, Relevant URI, Reference, Update URL]
     * @param array<string, array{0: string, 1: int}> $added rowKey => [Y-m-d first added, commit ordinal]
     *
     * @return array<string, array<string, mixed>> keyed by path
     */
    public function migrate(array $rows, array $added): array
    {
        // Assign ids in chronological order, per year.
        $order = [];
        foreach ($rows as $i => [$platform, $line, $name, , $uri]) {
            $key = self::rowKey($platform, $name, $uri);
            if (!isset($added[$key])) {
                throw new \RuntimeException("no history for $key");
            }
            $order[$i] = [...$added[$key], $platform, $line];
        }
        uksort($order, fn (int $a, int $b): int => $order[$a] <=> $order[$b]);

        $files = [];
        $counter = [];
        foreach (array_keys($order) as $i) {
            [$platform, , $name, $fixed, $uri, $reference, $update] = $rows[$i];
            $published = $order[$i][0];
            $year = substr($published, 0, 4);
            $counter[$year] = ($counter[$year] ?? 0) + 1;

            $module = ['module' => $name];
            if ($name !== '?') {
                if (str_starts_with($name, '_')) {
                    $module = ['module' => substr($name, 1), 'version_scheme' => 'nonstandard'];
                } elseif (str_ends_with($name, '?')) {
                    $module = ['module' => substr($name, 0, -1), 'notes' => 'Module name unconfirmed.'];
                }
                if ($update === 'Abandoned') {
                    $module['abandoned'] = true;
                } elseif ($update !== '') {
                    $module['update_url'] = self::url($update);
                }
            }

            $uris = array_values(array_filter(array_map(trim(...), explode(';', $uri)), strlen(...)));
            $adv = [
                'id' => sprintf('MVD-%s-%04d', $year, $counter[$year]),
                'title' => match (true) {
                    $name === '?' => "Unidentified module, $uris[0]",
                    $fixed === '' => "{$module['module']} vulnerability, unpatched",
                    default => "{$module['module']} vulnerability, fixed in $fixed",
                },
                'published' => $published,
            ];
            if ($uris) {
                $adv['uri'] = $uris;
            }
            if (filter_var($reference, FILTER_VALIDATE_URL)) {
                $adv['reference'] = $reference;
            } elseif ($reference !== '') {
                $adv['credit'] = $reference;
            }
            $adv['affected'] = $fixed === '' ? '*' : "<$fixed";

            $path = $platform . '/' . ($name === '?' ? Validator::UNKNOWN_FILE : $module['module'] . '.yaml');
            if (isset($files[$path]) && $name !== '?') {
                throw new \RuntimeException("duplicate module $path");
            }
            $files[$path] ??= $module + ['advisories' => []];
            $files[$path]['advisories'][] = $adv;
        }
        ksort($files, SORT_STRING);

        return $files;
    }

    private static function url(string $url): string
    {
        if (!filter_var($url, FILTER_VALIDATE_URL)) {
            throw new \RuntimeException("unexpected Update URL value: $url");
        }

        return $url;
    }
}
