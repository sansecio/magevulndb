<?php

declare(strict_types=1);

namespace MageVulnDb\Tests;

use MageVulnDb\CsvMigrator;
use MageVulnDb\Validator;
use PHPUnit\Framework\TestCase;

final class CsvMigratorTest extends TestCase
{
    /** Rows as [platform, line, Name, Fixed in, Relevant URI, Reference, Update URL]. */
    private const array ROWS = [
        ['m2', 2, 'Amasty_Acart', '1.21.0', '/amasty_acart/email/click', 'https://example.com/ref', 'https://example.com/upd'],
        ['m1', 5, 'PO_Prescription', '', '/a/;/b/', 'https://example.com/ref2', ''],
        ['m1', 6, '_Mirasvit_SEO', '1.3.16', '', 'https://mirasvit.com/x', 'https://mirasvit.com/y'],
        ['m1', 7, 'AW_AheadMetrics', '', '', 'Ryan Hoerr', 'Abandoned'],
        ['m1', 8, 'Amasty_Helpdesk?', '1.0.9', '', '', 'https://amasty.com/h'],
        ['m1', 9, '?', '', '/ajax/Showroom/submit/', 'https://example.com/0days', ''],
        ['m1', 10, '?', '', '/pdffree/Product/pdfsave/', "Peter O'Callaghan", ''],
    ];

    private function migrate(): array
    {
        // Same commit for most rows; ids follow (date, commit, platform, line).
        $added = [
            'm2|Amasty_Acart' => ['2019-03-01', 5],
            'm1|PO_Prescription' => ['2018-12-05', 0],
            'm1|Mirasvit_SEO' => ['2018-12-05', 0],
            'm1|AW_AheadMetrics' => ['2018-12-05', 0],
            'm1|Amasty_Helpdesk' => ['2018-12-05', 0],
            'm1|?|/ajax/Showroom/submit/' => ['2018-12-05', 0],
            'm1|?|/pdffree/Product/pdfsave/' => ['2019-03-01', 4],
        ];

        return (new CsvMigrator())->migrate(self::ROWS, $added);
    }

    public function testMigration(): void
    {
        $files = $this->migrate();

        $this->assertSame([
            'm1/AW_AheadMetrics.yaml', 'm1/Amasty_Helpdesk.yaml', 'm1/Mirasvit_SEO.yaml',
            'm1/PO_Prescription.yaml', 'm1/_unknown.yaml', 'm2/Amasty_Acart.yaml',
        ], array_keys($files));

        $this->assertSame([
            'module' => 'Amasty_Acart',
            'update_url' => 'https://example.com/upd',
            'advisories' => [[
                'id' => 'MVD-2019-0002',
                'title' => 'Amasty_Acart vulnerability, fixed in 1.21.0',
                'published' => '2019-03-01',
                'uri' => ['/amasty_acart/email/click'],
                'reference' => 'https://example.com/ref',
                'affected' => '<1.21.0',
            ]],
        ], $files['m2/Amasty_Acart.yaml']);

        $prescription = $files['m1/PO_Prescription.yaml']['advisories'][0];
        $this->assertSame('MVD-2018-0001', $prescription['id']);
        $this->assertSame(['/a/', '/b/'], $prescription['uri']);
        $this->assertSame('*', $prescription['affected']);
        $this->assertSame('PO_Prescription vulnerability, unpatched', $prescription['title']);

        $mirasvit = $files['m1/Mirasvit_SEO.yaml'];
        $this->assertSame('Mirasvit_SEO', $mirasvit['module']);
        $this->assertSame('nonstandard', $mirasvit['version_scheme']);
        $this->assertSame('<1.3.16', $mirasvit['advisories'][0]['affected']);

        $aw = $files['m1/AW_AheadMetrics.yaml'];
        $this->assertTrue($aw['abandoned']);
        $this->assertArrayNotHasKey('update_url', $aw);
        $this->assertSame('Ryan Hoerr', $aw['advisories'][0]['credit']);
        $this->assertArrayNotHasKey('reference', $aw['advisories'][0]);

        $helpdesk = $files['m1/Amasty_Helpdesk.yaml'];
        $this->assertSame('Amasty_Helpdesk', $helpdesk['module']);
        $this->assertSame('Module name unconfirmed.', $helpdesk['notes']);

        $unknown = $files['m1/_unknown.yaml'];
        $this->assertSame('?', $unknown['module']);
        $this->assertSame(['MVD-2018-0005', 'MVD-2019-0001'], array_column($unknown['advisories'], 'id'));
        $this->assertSame('Unidentified module, /ajax/Showroom/submit/', $unknown['advisories'][0]['title']);
    }

    public function testOutputValidates(): void
    {
        $this->assertSame([], (new Validator())->validate($this->migrate()));
    }

    public function testRowKey(): void
    {
        $this->assertSame('m1|?|/x/', CsvMigrator::rowKey('m1', '?', '/x/'));
        $this->assertSame('m2|Foo_Bar', CsvMigrator::rowKey('m2', 'Foo_Bar', '/x/'));
        $this->assertSame('m1|Mirasvit_SEO', CsvMigrator::rowKey('m1', '_Mirasvit_SEO', ''));
        $this->assertSame('m1|Amasty_Helpdesk', CsvMigrator::rowKey('m1', 'Amasty_Helpdesk?', ''));
    }
}
