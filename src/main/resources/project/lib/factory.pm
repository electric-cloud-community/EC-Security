# -*- Perl -*-

package factory;

use strict;
use ElectricCommander;
use policy;
use JSON;

$|=1;

sub main {
    my $ec = new ElectricCommander({abortOnError => 0, format => 'json'});

    # Load the policy location and the policy

    my $batch = $ec->newBatch();
    my @reqs = (
        $batch->expandString(q{$[objectType]}),
        $batch->expandString(q{$[objectName]}),
        $batch->expandString(q{$[team]}),
        $batch->expandString(q{$[/myProject/currentPolicy]}),
        $batch->expandString(q{$[launchedByUser]}),
    );
    $batch->submit();

    my ($objectType, $objectName, $team, $policyLocation,
        $user) = map { $batch->findvalue($_, 'value') } @reqs;

    if (!$policyLocation) {
        die "No security policy is currently in effect for this system.  Use the ApplyPolicy procedure as user 'admin' to establish a security policy.\n";
    }

    my @groups = $ec->getUser($user)->findnodes('//groupName');

    if (!policy::isTeamObjType($objectType)) {
        die "Unexpected object type.  Must be one of: "
        . join(", ", @policy::teamObjTypes) . "\n";
    }

    print "Using policy loaded from: $policyLocation\n";
    print "Creating $objectType\[$objectName\]\n";
    print "Granting permission to team: $team\n";

    my $policy = new policy($ec, $policyLocation);

    if ($user ne 'admin'
        && !$policy->checkCreate($objectType, $team, \@groups)) {
        die "User $user is not allowed to create ${objectType}s for team $team\n";
    }

    $policy->attachTeamToObject($team, $objectType, $objectName);

    my $update = $ec->newBatch('single');

    $policy->createObject($update, $objectType, $objectName);
    $policy->updatePolicy($update);

    my $response = $update->submit();

    my $errorMsg = $ec->getError();
    my $exitCode = 0;
    if ($errorMsg) {
        $errorMsg =~ s/.*BatchFailed.*\n?//g;
        $errorMsg =~ s/\n+$//;
        print "Update failed:\n\n".$errorMsg;
        $exitCode = 1;
    }
    my $json = JSON->new->utf8->pretty->canonical;
    print "\n\nDetails:\n\nRequests:\n", $json->encode($update->{requests});
    print "\nResults:\n";
    print $json->encode({%{$response}});
    exit($exitCode);
}

1;

