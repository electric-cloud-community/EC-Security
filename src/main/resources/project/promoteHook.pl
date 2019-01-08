# -*- Perl -*-

# This script is called by the ElectricCommander promote api after the
# plugin's ec_setup script is invoked.  This script will arrange for the
# current security policy to be applied to the plugin by calling the
# ApplyToObject procedure.  The procedure is only invoked if the server
# has a license and there is a non-empty policy name.

my $xpath = $commander->getProperty(
    '/plugins/@PLUGIN_NAME@/project/currentPolicy');
if ($xpath->findvalue('//value') ne ''
    && $xpath->findvalue('//advisoryMessage') !~ m/A Server license/) {

    my $requestId = $batch->runProcedure('/plugins/@PLUGIN_NAME@/project', {
        procedureName => 'ApplyPolicyToPlugin',
        actualParameter => [{ actualParameterName => 'pluginName',
                              value => $pluginName }],
    });

    $responseHandler = sub {
        my $jobId = $batch->findValue($requestId, '//jobId');
        # Wait up to half an hour for the job to complete.
        $commander->waitForJob($jobId, 1800);
    }
}
