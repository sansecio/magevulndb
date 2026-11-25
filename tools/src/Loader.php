<?php

declare(strict_types=1);

namespace MageVulnDb;

use Symfony\Component\Yaml\Exception\ParseException;
use Symfony\Component\Yaml\Yaml;

/** Reads the module YAML files under m1/ and m2/. */
final class Loader
{
    public const array DIRS = ['m1', 'm2'];

    /**
     * Loads every file under m1/ and m2/ of $root.
     *
     * @return array{0: array<string, mixed>, 1: list<string>} parsed data keyed by relative path, and errors
     */
    public function load(string $root): array
    {
        $files = [];
        $errors = [];
        foreach (self::DIRS as $dir) {
            if (!is_dir("$root/$dir")) {
                continue;
            }
            $it = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator("$root/$dir", \FilesystemIterator::SKIP_DOTS));
            foreach ($it as $file) {
                $rel = substr($file->getPathname(), strlen($root) + 1);
                if (!str_ends_with($rel, '.yaml')) {
                    $errors[] = "$rel: only .yaml files belong in $dir/";
                    continue;
                }
                try {
                    $files[$rel] = self::normalize(Yaml::parseFile($file->getPathname(), Yaml::PARSE_DATETIME | Yaml::PARSE_EXCEPTION_ON_INVALID_TYPE));
                } catch (ParseException $e) {
                    $errors[] = "$rel: " . $e->getMessage();
                }
            }
        }
        ksort($files, SORT_STRING);
        sort($errors, SORT_STRING);

        return [$files, $errors];
    }

    /** Turns unquoted YAML dates into Y-m-d strings, so `published: 2025-04-11` and `published: "2025-04-11"` are equal. */
    private static function normalize(mixed $v): mixed
    {
        if ($v instanceof \DateTimeInterface) {
            return $v->format('Y-m-d');
        }
        if (is_array($v)) {
            return array_map(self::normalize(...), $v);
        }

        return $v;
    }
}
