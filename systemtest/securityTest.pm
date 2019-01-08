# -*-Perl-*-

# securityTest -
#
# Test utilities to help testing the EC-Security plugin.
#
# Copyright (c) 2005-2010 Electric Cloud, Inc.
# All rights reserved

package securityTest;

use strict;
use warnings;
use Assert;
use ECTest;
use Exporter;

our @EXPORT = qw(applyPolicy createObject assertAcl);

my $gTimeout = 600;

sub applyPolicy
{
    my ($policyPath, $expectedOutcome, $session) = @_;
    $session ||= $adminSession;

    my $actuals = [ { actualParameterName => 'policyLocation',
                               value => $policyPath } ];
    return runProc($session, 'ApplyPolicy', 'Apply', $actuals,
                   $expectedOutcome);
}

sub createObject
{
    my ($objectName, $objectType, $team, $expectedOutcome, $session) = @_;
    $session ||= $guestSession;
    my $actuals = [ { actualParameterName => 'objectName',
                      value => $objectName },
                    { actualParameterName => 'objectType',
                      value => $objectType },
                    { actualParameterName => 'team',
                      value => $team } ];
    return runProc($session, 'CreateObject', 'Create', $actuals,
                   $expectedOutcome);
}

sub runProc{
    my ($session, $procName, $stepName, $actuals, $expectedOutcome) = @_;
    $expectedOutcome ||= 'success';
    my $xpath = $session->runProcedure('/plugins/EC-Security/project', {
        procedureName => $procName,
        pollInterval => '0.2',
        timeout      => $gTimeout,
        actualParameter => $actuals
    });
    assertDef($xpath, "finished without a timeout");

    if ($xpath) {
        my $jobId  = $xpath->findvalue('//jobId');
        my $status = $xpath->findvalue('//status');
        my $outcome = $xpath->findvalue('//outcome');

        assertTrue($jobId && $jobId ne "", 'valid job id');
        assertEq('completed', $status, "job $jobId completed");

        # Abort the job if it hasn't completed
        if ($status ne 'completed') {
            assertOK($session->abortJob($jobId, {force => 1}));
        }

        if ($jobId) {
            assertOK($xpath = $session->getJobDetails($jobId));
            my $log = readStepLogFile($xpath, $stepName);
            assertEq($expectedOutcome, $outcome, "job $jobId $expectedOutcome");
            if ($outcome ne $expectedOutcome) {
                fail('Output log: '.$log);
            }
            return wantarray ? ($log, $jobId) : $log;
        }
    }
}

sub assertAcl {
    my $privs = pop @_;
    my $loc = pop @_;
    my $name = pop @_;
    my $type = pop @_ || "group";
    my $msg = join(" ",(%{$loc}))." $type $name";
    my $xpath = $adminSession->getAclEntry($type, $name, $loc);
    my $code = $xpath->findvalue("//code");
    assertEq('', $code, "ace exists $msg");
    return if ($code);

    my @nodes = $xpath->findnodes('//aclEntry');
    my $node = $nodes[0];
    foreach ('read', 'modify', 'execute', 'changePermissions') {
        assertEq(shift @{$privs}, $node->findvalue($_."Privilege"),
                 "$msg $_");
    }
}

1;
