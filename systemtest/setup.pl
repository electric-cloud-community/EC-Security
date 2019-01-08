#-------------------------------------------------------------------------
# setup.pl -
#
# Perform setup steps needed by the test suite.  Clears out state that
# might interfere with the tests and installs the plugin to test.
#-------------------------------------------------------------------------

use strict;
use ElectricCommander;
use Cwd;

$|=1;

my $N = new ElectricCommander({
    server => 'localhost',
    abortOnError => 0
});

$N->login('admin','changeme');


# Demote the security module so the plugin installation hook isn't
# registered.  This will prevent pontential interference with other
# tests.

print "Demoting EC-Security\n";
$N->promotePlugin('EC-Security', {promoted => 0});
