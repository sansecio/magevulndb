<?php

declare(strict_types=1);

namespace MageVulnDb\Tests;

use MageVulnDb\Builder;
use MageVulnDb\Cvss;
use PHPUnit\Framework\TestCase;

final class BuilderTest extends TestCase
{
    private function files(): array
    {
        $m2 = ValidatorTest::module();
        $m2['composer'][] = 'foo/marketplace-bar';
        $m2['advisories'][] = [
            'id' => 'MVD-2024-0007', 'title' => 'SQL injection', 'published' => '2024-01-02',
            'cve' => 'CVE-2024-12345', 'affected' => '<3.0',
        ];

        return [
            'm2/Foo_Bar.yaml' => $m2,
            'm2/Aaa_Bbb.yaml' => ['module' => 'Aaa_Bbb', 'advisories' => [[
                'id' => 'MVD-2020-0001', 'title' => 'x', 'published' => '2020-01-01', 'affected' => '*',
            ]]],
            'm1/Old_One.yaml' => ['module' => 'Old_One', 'version_scheme' => 'nonstandard', 'advisories' => [[
                'id' => 'MVD-2019-0001', 'title' => 'y', 'published' => '2019-01-01', 'affected' => '<1.5',
            ]]],
        ];
    }

    public function testJson(): void
    {
        $json = (new Builder())->json($this->files(), new \DateTimeImmutable('2026-01-02T03:04:05Z'));

        $this->assertSame(1, $json['format']);
        $this->assertSame('2026-01-02T03:04:05Z', $json['generated_at']);
        $this->assertSame(['Old_One'], array_column($json['m1'], 'module'));
        $this->assertSame(['Aaa_Bbb', 'Foo_Bar'], array_column($json['m2'], 'module'));
        $this->assertSame('nonstandard', $json['m1'][0]['version_scheme']);

        $adv = $json['m2'][1]['advisories'];
        $this->assertSame('critical', $adv[0]['severity']); // 3.1 vector scores 9.1
        $this->assertSame('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N', $adv[0]['cvss']);
        $this->assertArrayNotHasKey('severity', $adv[1]);
    }

    public function testComposerRepository(): void
    {
        $out = (new Builder())->composerRepository($this->files(), 'https://sansecio.github.io/magevulndb/');

        $this->assertSame(['packages.json', 'p2/foo/marketplace-bar.json', 'p2/foo/module-bar.json'], array_keys($out));

        $packages = $out['packages.json'];
        $this->assertSame([], $packages['packages']);
        $this->assertSame('https://sansecio.github.io/magevulndb/p2/%package%.json', $packages['metadata-url']);
        $this->assertSame(['foo/marketplace-bar', 'foo/module-bar'], $packages['available-packages']);
        $this->assertSame(['metadata' => true], $packages['security-advisories']);

        $advisories = $out['p2/foo/module-bar.json']['security-advisories'];
        $this->assertCount(2, $advisories);
        $this->assertSame([
            'advisoryId' => 'MVD-2025-0001',
            'packageName' => 'foo/module-bar',
            'title' => 'Unauthenticated webhook access',
            'affectedVersions' => '>=4.0,<4.4.2 || <3.5.9',
            'sources' => [['name' => 'MageVulnDB', 'remoteId' => 'MVD-2025-0001']],
            'reportedAt' => '2025-04-11 00:00:00',
            'cve' => null,
            'link' => 'https://example.com/changelog',
            'severity' => 'critical',
        ], $advisories[0]);
        $this->assertSame('CVE-2024-12345', $advisories[1]['cve']);
        $this->assertNull($advisories[1]['severity']);
        $this->assertSame('foo/marketplace-bar', $out['p2/foo/marketplace-bar.json']['security-advisories'][0]['packageName']);
    }

    public function testSeverityBands(): void
    {
        $this->assertSame('medium', Cvss::severity('CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N')); // 5.4
        $this->assertSame('high', Cvss::severity('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N')); // 8.7
        $this->assertSame('none', Cvss::severity('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N'));
    }
}
