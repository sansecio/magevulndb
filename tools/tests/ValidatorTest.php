<?php

declare(strict_types=1);

namespace MageVulnDb\Tests;

use MageVulnDb\Loader;
use MageVulnDb\Validator;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class ValidatorTest extends TestCase
{
    public static function module(array $advisory = [], array $module = []): array
    {
        return $module + [
            'module' => 'Foo_Bar',
            'composer' => ['foo/module-bar'],
            'update_url' => 'https://example.com/foo-bar',
            'advisories' => [$advisory + [
                'id' => 'MVD-2025-0001',
                'title' => 'Unauthenticated webhook access',
                'published' => '2025-04-11',
                'cvss' => 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N',
                'known_exploited' => false,
                'uri' => ['/foo/webhook'],
                'reference' => 'https://example.com/changelog',
                'affected' => '>=4.0,<4.4.2 || <3.5.9',
            ]],
        ];
    }

    public function testValidModule(): void
    {
        $this->assertSame([], (new Validator())->validate(['m2/Foo_Bar.yaml' => self::module()]));
    }

    public static function invalidCases(): iterable
    {
        yield 'unknown key' => ['m2/Foo_Bar.yaml', self::module(['severity' => 'high']), 'severity'];
        yield 'missing title' => ['m2/Foo_Bar.yaml', self::module(['title' => ''])];
        yield 'filename mismatch' => ['m2/Foo_Baz.yaml', self::module(), 'does not match module'];
        yield 'wrong dir' => ['m3/Foo_Bar.yaml', self::module(), 'm1/ or m2/'];
        yield 'nested dir' => ['m2/x/Foo_Bar.yaml', self::module(), 'm1/ or m2/'];
        yield 'bad constraint' => ['m2/Foo_Bar.yaml', self::module(['affected' => '<1.2.3 ||']), 'affected'];
        yield 'bad constraint word' => ['m2/Foo_Bar.yaml', self::module(['affected' => 'all versions']), 'affected'];
        yield 'cvss 3.0' => ['m2/Foo_Bar.yaml', self::module(['cvss' => 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N'])];
        yield 'cvss 3.1 incomplete' => ['m2/Foo_Bar.yaml', self::module(['cvss' => 'CVSS:3.1/AV:N/AC:L']), 'cvss'];
        yield 'cvss 4.0 bad metric' => ['m2/Foo_Bar.yaml', self::module(['cvss' => 'CVSS:4.0/AV:X/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N']), 'cvss'];
        yield 'reference not url' => ['m2/Foo_Bar.yaml', self::module(['reference' => 'Ryan Hoerr'])];
        yield 'update_url not url' => ['m2/Foo_Bar.yaml', self::module([], ['update_url' => 'Abandoned'])];
        yield 'bad id' => ['m2/Foo_Bar.yaml', self::module(['id' => 'MVD-25-1'])];
        yield 'bad date' => ['m2/Foo_Bar.yaml', self::module(['published' => '2025-13-45'])];
        yield 'bad composer name' => ['m2/Foo_Bar.yaml', self::module([], ['composer' => ['Foo/Bar']])];
        yield 'unknown module outside _unknown' => ['m1/Foo_Bar.yaml', self::module([], ['module' => '?'])];
        yield '_unknown with real module' => ['m1/_unknown.yaml', self::module(), '_unknown.yaml'];
    }

    #[DataProvider('invalidCases')]
    public function testInvalid(string $path, array $data, ?string $needle = null): void
    {
        $errors = (new Validator())->validate([$path => $data]);
        $this->assertNotEmpty($errors);
        foreach ($errors as $error) {
            $this->assertStringStartsWith($path . ':', $error);
        }
        if ($needle !== null) {
            $this->assertStringContainsString($needle, implode("\n", $errors));
        }
    }

    public function testCvss40Accepted(): void
    {
        $data = self::module(['cvss' => 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N']);
        $this->assertSame([], (new Validator())->validate(['m2/Foo_Bar.yaml' => $data]));
    }

    public function testUnknownFile(): void
    {
        $data = ['module' => '?', 'advisories' => [[
            'id' => 'MVD-2018-0001', 'title' => 'x', 'published' => '2018-10-23',
            'uri' => ['/ajax/Showroom/submit/'], 'affected' => '*',
        ]]];
        $this->assertSame([], (new Validator())->validate(['m1/_unknown.yaml' => $data]));
    }

    public function testDuplicateIdAcrossFiles(): void
    {
        $errors = (new Validator())->validate([
            'm1/Foo_Bar.yaml' => self::module(),
            'm2/Foo_Bar.yaml' => self::module(),
        ]);
        $this->assertCount(1, $errors);
        $this->assertStringContainsString('MVD-2025-0001', $errors[0]);
        $this->assertStringContainsString('m1/Foo_Bar.yaml', $errors[0]);
    }

    public function testLoaderNormalizesDatesAndReportsParseErrors(): void
    {
        $root = sys_get_temp_dir() . '/mvd-' . bin2hex(random_bytes(4));
        mkdir("$root/m2", 0o777, true);
        file_put_contents("$root/m2/Foo_Bar.yaml", "module: Foo_Bar\nadvisories:\n  - id: MVD-2025-0001\n    title: x\n    published: 2025-04-11\n    affected: '<1.0'\n");
        file_put_contents("$root/m2/Broken.yaml", "module: [\n");
        file_put_contents("$root/m2/Foo_Baz.yml", "module: Foo_Baz\n");

        [$files, $errors] = (new Loader())->load($root);

        $this->assertSame(['m2/Foo_Bar.yaml'], array_keys($files));
        $this->assertSame('2025-04-11', $files['m2/Foo_Bar.yaml']['advisories'][0]['published']);
        $this->assertCount(2, $errors);
        $this->assertStringStartsWith('m2/Broken.yaml:', $errors[0]);
        $this->assertStringContainsString('.yaml', $errors[1]);
    }
}
