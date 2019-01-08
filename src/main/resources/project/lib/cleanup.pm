# -*- Perl -*-

package cleanup;

use strict;
use File::Path;
use ElectricCommander;
use POSIX qw(strftime);

# Set autoflush
$| = 1;

sub main {
    my $ec = new ElectricCommander({abortOnError => 0, format => 'json'});

    my $batch = $ec->newBatch();
    my @reqs = ($batch->expandString('$[/myProject]'),
                $batch->expandString('$[/myProcedure]'));
    $batch->submit();

    my $yesterday = time() - 60*60*24;
    my $dateOperand = strftime("%Y-%m-%dT%H:%M:%S.000", localtime($yesterday));

    my $result = $ec->findObjects('job', {
        maxIds => 500,
        numObjects => 500,
        filter => [ { propertyName => 'projectName',
                      operator => 'equals',
                      operand1 => $batch->find($reqs[0])->findvalue("value") },
                    { propertyName => 'procedureName',
                      operator => 'equals',
                      operand1 => $batch->find($reqs[1])->findvalue("value") },
                    { propertyName => 'status',
                      operator => 'equals',
                      operand1 => 'completed' },
                    { operator => 'or',
                      filter => [
                          { propertyName => 'outcome',
                            operator => 'equals',
                            operand1 => 'success' },
                          { propertyName => 'finish',
                            operator => 'lessThan',
                            operand1 => $dateOperand }
                      ]}
                ],
    });

    foreach my $job ($result->findnodes('//job')) {
        #  Find the workspaces (there can be more than one if some steps
        #  were configured to use a different workspace
        my $jobId = $job->{jobId};
        my $jobName = $job->{jobName};
        rmtree("../$jobName");
        print "Deleted workspace - ../$jobName\n";
        $ec->deleteJob($jobId);
        print "Deleted job - $jobName\n";
    }
}

1;

