<?php

declare(strict_types=1);

namespace MageVulnDb;

use Rootshell\Cvss\Cvss as Calculator;

/** CVSS 3.1 and 4.0 vector checks and severity bands. */
final class Cvss
{
    /**
     * Returns the qualitative severity (none, low, medium, high, critical) of a CVSS 3.1 or 4.0 vector.
     *
     * @throws \InvalidArgumentException when the vector is not a complete 3.1 or 4.0 base vector
     */
    public static function severity(string $vector): string
    {
        if (!preg_match('{^CVSS:(3\.1|4\.0)/}', $vector)) {
            throw new \InvalidArgumentException('must start with CVSS:3.1/ or CVSS:4.0/');
        }
        try {
            $score = Calculator::generateScores($vector)->baseScore;
        } catch (\Throwable $e) {
            throw new \InvalidArgumentException($e->getMessage(), 0, $e);
        }

        return match (true) {
            $score >= 9.0 => 'critical',
            $score >= 7.0 => 'high',
            $score >= 4.0 => 'medium',
            $score > 0.0 => 'low',
            default => 'none',
        };
    }
}
