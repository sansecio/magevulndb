<?php

declare(strict_types=1);

namespace MageVulnDb;

use Composer\Semver\VersionParser;
use JsonSchema\Constraints\Constraint;
use JsonSchema\Validator as SchemaValidator;

/** Checks module files against the schema and the rules the schema cannot express. */
final class Validator
{
    public const string UNKNOWN_FILE = '_unknown.yaml';

    private readonly object $schema;
    private readonly VersionParser $parser;

    public function __construct(?string $schemaPath = null)
    {
        $schemaPath ??= dirname(__DIR__, 2) . '/schema/module.schema.json';
        $this->schema = json_decode((string) file_get_contents($schemaPath), flags: JSON_THROW_ON_ERROR);
        $this->parser = new VersionParser();
    }

    /**
     * Validates all files at once (ids must be unique across them).
     *
     * @param array<string, mixed> $files parsed data keyed by repository-relative path
     *
     * @return list<string> errors, each prefixed with "path:"
     */
    public function validate(array $files): array
    {
        $errors = [];
        $seen = [];
        foreach ($files as $path => $data) {
            foreach ($this->validateFile($path, $data) as $e) {
                $errors[] = "$path: $e";
            }
            foreach (is_array($data) ? $data['advisories'] ?? [] : [] as $adv) {
                $id = is_array($adv) ? $adv['id'] ?? null : null;
                if (!is_string($id)) {
                    continue;
                }
                if (isset($seen[$id])) {
                    $errors[] = "$path: id $id already used in {$seen[$id]}";
                } else {
                    $seen[$id] = $path;
                }
            }
        }

        return $errors;
    }

    /** @return list<string> */
    private function validateFile(string $path, mixed $data): array
    {
        $errors = [];
        if (!preg_match('{^m[12]/[^/]+\.yaml$}', $path)) {
            $errors[] = 'files must be directly in m1/ or m2/';
        }

        $doc = json_decode(json_encode($data, JSON_THROW_ON_ERROR));
        $v = new SchemaValidator();
        $v->validate($doc, $this->schema, Constraint::CHECK_MODE_NORMAL);
        foreach ($v->getErrors() as $e) {
            $errors[] = ($e['property'] !== '' ? $e['property'] . ': ' : '') . $e['message'];
        }
        if (!is_array($data)) {
            return $errors;
        }

        $module = $data['module'] ?? null;
        $file = basename($path);
        if ($file === self::UNKNOWN_FILE || $module === '?') {
            if ($file !== self::UNKNOWN_FILE || $module !== '?') {
                $errors[] = "module '?' belongs in " . self::UNKNOWN_FILE . ' and nowhere else';
            }
        } elseif (is_string($module) && $file !== "$module.yaml") {
            $errors[] = "file name does not match module $module";
        }

        foreach ($data['advisories'] ?? [] as $i => $adv) {
            if (!is_array($adv)) {
                continue;
            }
            if (is_string($adv['affected'] ?? null)) {
                try {
                    $this->parser->parseConstraints($adv['affected']);
                } catch (\UnexpectedValueException $e) {
                    $errors[] = "advisories[$i].affected: " . $e->getMessage();
                }
            }
            if (is_string($adv['cvss'] ?? null)) {
                try {
                    Cvss::severity($adv['cvss']);
                } catch (\InvalidArgumentException $e) {
                    $errors[] = "advisories[$i].cvss: " . $e->getMessage();
                }
            }
        }

        return $errors;
    }
}
