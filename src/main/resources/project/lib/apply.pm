# -*- Perl -*-

package apply;

use strict;
use ElectricCommander;
use policy;
use JSON;

$|=1;

#-------------------------------------------------------------------------
# changePolicy
#
#       Apply the security policy referenced by the 'policyLocation'
#       property (passed as an argument to the procedure).
#-------------------------------------------------------------------------
sub changePolicy {
    my $ec = new ElectricCommander({abortOnError => 0, format => 'json'});

    # Load the policy location and the policy

    my $batch = $ec->newBatch();
    my @reqs = (
        $batch->expandString(q{$[policyLocation]}),
        $batch->expandString(q{$[/myProject/currentPolicy]}),
        $batch->expandString(q{$[launchedByUser]}),
    );
    $batch->submit();

    my ($policyLocation, $oldPolicyLocation, $launchedBy) = map {
        $batch->findvalue($_,'value') } @reqs;

    if ($launchedBy ne 'admin') {
        print "Only user 'admin' is allowed to change security policies\n";
        exit(1);
    }
    print "Current policy: $oldPolicyLocation\n";
    print "Applying policy loaded from: $policyLocation\n";

    my $policy = new policy($ec, $policyLocation);

    my $update = $ec->newBatch('single');
    $policy->apply($update);

    my $exitCode = 0;

    if ($update->size()) {
        my $response = $update->submit();
        my $errorMsg = $ec->getError();
        if ($errorMsg) {
            $errorMsg =~ s/.*BatchFailed.*\n?//g;
            $errorMsg =~ s/\n+$//;
            print "Update failed:\n\n".$errorMsg;
            $exitCode = 1;
        }

        my $json = JSON->new->utf8->pretty->canonical;
        print "\n\nDetails:\n\nRequests:\n";
        print $json->encode($update->{requests}),"\n";
        print "Results:\n";
        print $json->encode({%{$response}});
    } else {
        print "No changes requested\n";
    }

    $ec->setProperty('/myProject/currentPolicy', $policyLocation);
    exit($exitCode);
}

#-------------------------------------------------------------------------
# applyToPlugin
#
#       Apply the current policy to the specified plugin
#       (passed as an argument to the procedure).
#-------------------------------------------------------------------------
sub applyToPlugin {
    my $ec = new ElectricCommander({abortOnError => 0, format => 'json'});

    # Load the policy location and the policy

    my $batch = $ec->newBatch();
    my @reqs = (
        $batch->expandString(q{$[pluginName]}),
        $batch->expandString(q{$[/myProject/currentPolicy]}),
    );
    $batch->submit();

    my ($pluginName, $policyLocation) = map {
        $batch->findvalue($_,'value') } @reqs;

    print "Using policy loaded from: $policyLocation\n";
    print "Applying policy to plugin: $pluginName\n";

    my $policy = new policy($ec, $policyLocation);

    my $update = $ec->newBatch('single');

    $policy->applyToObjects('plugin', $update, $pluginName);

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
    print "\n\nDetails:\n\nRequests:\n",$json->encode($update->{requests}),"\n";
    print "Results:\n";
    print $json->encode({%{$response}});
    exit($exitCode);

}

#-------------------------------------------------------------------------
# changePolicyForAllPlugins
#
#       Apply the current policy to all plugins.
#-------------------------------------------------------------------------
sub changePolicyForAllPlugins {
    my $ec = new ElectricCommander({abortOnError => 0, format => 'json'});

    # Load the policy location and the policy, if any.  If none, we have
    # no work to do.

    my $batch = $ec->newBatch();
    my @reqs = (
        $batch->expandString(q{$[/myProject/currentPolicy]}),
        $batch->expandString(q{$[launchedByUser]}),
    );
    my $xpath = $batch->submit();

    my ($policyLocation, $launchedBy) = map {
        $batch->findvalue($_,'value') } @reqs;

    if ($policyLocation eq '') {
        print "No security policy to apply.\n";
        exit(0);
    }
    if ($launchedBy ne 'admin') {
        print "Only user 'admin' is allowed to change security policies\n";
        exit(1);
    }
    print "Applying policy to all plugins.\n";
    print "Applying policy loaded from: $policyLocation\n";

    my $policy = new policy($ec, $policyLocation);

    my $update = $ec->newBatch('single');
    my $rules = $policy->{'plugin'};
    $policy->handlePlugin($update, $rules);

    my $exitCode = 0;

    if ($update->size()) {
        print join("\n", @{$update->{requests}});
        my $response = $update->submit();
        my $errorMsg = $ec->getError();
        if ($errorMsg) {
            $errorMsg =~ s/.*BatchFailed.*\n?//g;
            $errorMsg =~ s/\n+$//;
            print "Update failed:\n\n".$errorMsg;
            $exitCode = 1;
        }

        my $json = JSON->new->utf8->pretty->canonical;
        print "\n\nDetails:\n\nRequests:\n";
        print $json->encode($update->{requests}),"\n";
        print "Results:\n";
        print $json->encode({%{$response}});
    } else {
        print "No changes requested\n";
    }

    exit($exitCode);
}

1;

