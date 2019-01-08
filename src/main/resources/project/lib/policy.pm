# -*- Perl -*-

package policy;

use strict;
use JSON;
use Data::Dumper;

# teamObjTypes are objects that can be associated with a team
our @teamObjTypes = qw(artifact project resource workspace);

our @allObjTypes = (@teamObjTypes, 'systemObject', 'propertySheet', 'plugin',
                'emailConfig', 'repository', 'zone', 'gateway');

#-------------------------------------------------------------------------
# constructor
#
#       Loads a security policy from the specified property, parses
#       it, and builds various indices.
#
# Arguments:
#       $cmdr           - The commander object to use for queries, must be
#                         using 'json' format.
#       $policyLocation - The path to the property containing the policy.
#-------------------------------------------------------------------------

sub new {
    my ($class, $cmdr, $policyLocation) = @_;

    # Load the policy and its timestamp
    my $batch = $cmdr->newBatch();
    my @reqs = (
        $batch->getProperty($policyLocation),
        $batch->evalScript(
            qq{getProperty("$policyLocation").modifyTime.time;})
    );
    $batch->submit();

    my $policyScript = $batch->findvalue($reqs[0], 'property/value');
    my $readTime = $batch->findvalue($reqs[1], 'value');
    if (!$policyScript) {
        die "Unable to find policy in '$policyLocation'\n";
    }

    my $self = bless {
        cmdr => $cmdr,
        policyLocation => $policyLocation,
        baseTime => $readTime
    };

    # Parse the policy
    my $policy;
    eval { $policy = decode_json($policyScript) };
    if (ref $policy ne 'HASH') {
        die "Unable to decode policy: $@\n$policyScript\n";
    }
    $self->{policy} = $policy;

    # Determine the set of groups managed by the policy
    if (exists $policy->{managedGroups}) {
        $self->{managedGroups}->{$_} = 1 foreach @{
            $policy->{managedGroups}};
    }
    if (exists $policy->{managedUsers}) {
        $self->{managedUsers}->{$_} = 1 foreach @{
            $policy->{managedUsers}};
    }
    if (exists $policy->{teams}) {
        # Build the inverted roles index
        while (my ($name, $team) = each %{$policy->{teams}}) {
            $self->addTeamToIndex($name, $team);
        }
    }

    # Copy the object type rules to the top hash
    foreach my $objType (@allObjTypes) {
        my $rules = $policy->{$objType};
        next unless $rules;
        if (ref $rules ne 'ARRAY') {
            die "Value for type '$objType' must be an array\n";
        }
        if ($objType eq 'systemObject') {
            # Restructure system object rules for easier direct access
            my %hashRules = map { $_->{name}, $_->{acl} } @{$rules};
            $rules = \%hashRules;
        }
        $self->{$objType} = $rules;
    }

    return $self;
}

#-------------------------------------------------------------------------
# updatePolicy
#
#       Write the modified policy back to the original policy location.
#       Adds an assertion to guard against simultaneous updates.
#-------------------------------------------------------------------------
sub updatePolicy {
    my ($self, $update) = @_;

    # Add an assertion that the policy hasn't been updated by someone else
    my $path = $self->{policyLocation};
    my $baseTime = $self->{baseTime};
    $update->evalScript(
        qq{getProperty("$path").modifyTime.time == $baseTime || fail()});

    my $policy = JSON->new->utf8->pretty->canonical->encode($self->{policy});
    $update->setProperty($path, $policy);
}

#-------------------------------------------------------------------------
# addTeamToIndex
#
#       Add groups mentioned in the team to the list of managed groups.
#       Build role maps for any objects associated with the team.
#-------------------------------------------------------------------------
sub addTeamToIndex {
    my ($self, $name, $team) = @_;
    my $roles = $team->{roles};

    # Define the global object role map.
    while (my ($roleName, $role) = each %{$roles}) {
        my $group = $role->{group};
        push(@{$self->{roleMap}->{global}->{$roleName}}, $group);
        $self->{managedGroups}->{$group} = 1;
    }

    # Define team object type role maps.
    foreach my $objType (@teamObjTypes) {
        my $objNames = $team->{$objType};
        next unless $objNames;

        foreach my $objName (@{$objNames}) {
           while (my ($roleName, $role) = each %{$roles}) {
                my $group = $role->{group};
                push(@{$self->{roleMap}->{$objType}->{$objName}->{$roleName}},
                     $group);
                $self->{managedGroups}->{$group} = 1;
            }
        }
    }
}


#-------------------------------------------------------------------------
# attachTeamToObject
#
#       Associate a newly created object with the specified team.
#-------------------------------------------------------------------------
sub attachTeamToObject {
    my ($self, $teamName, $objType, $objName) = @_;
    my $team = $self->{policy}->{teams}->{$teamName};

    if ($team) {

        my $names = $team->{$objType};
        my %hash = map { $_, 1 } @{$names};
        $hash{$objName} = 1;
        my @names = sort keys %hash;
        $team->{$objType} = \@names;
        my $roles = $team->{roles};
        foreach my $roleName (keys %{$roles}) {
            my $group = $roles->{$roleName}->{group};
            push(@{$self->{roleMap}->{$objType}->{$objName}->{$roleName}},
                 $group);
        }
    }
}

#-------------------------------------------------------------------------
# applyToObjects
#
#       Apply the current policy to the specified objects.
#-------------------------------------------------------------------------
sub applyToObjects {
    my ($self, $objectType, $update, @objectNames) = @_;

    my $rules = $self->{$objectType};
    $self->doHandleObjects($objectType, $update, $rules, @objectNames);
}

#-------------------------------------------------------------------------
# createObject
#
#       Create a new object and apply the policy to it.
#-------------------------------------------------------------------------
sub createObject {
    my ($self, $update, $objectType, $objectName) = @_;

    my $op = 'create'.ucfirst($objectType);
    if ($objectType eq 'artifact') {
        my @args = split(/:/,$objectName,2);
        if (@args != 2) {
            die "ERROR: Unable to parse artifact name '$objectName': Artifact names must be of the form groupId:artifactKey\n";
        }
        $update->$op(@args);
    } else {
        $update->$op($objectName);
    }

    my $acl = {};
    my $rules = $self->{$objectType};
    my $roleMap = $self->{roleMap}->{$objectType}->{$objectName};

    foreach my $rule (@{$rules}) {
        if ($objectName =~ $rule->{pattern}) {
            applyRule($acl, $rule->{acl}, $roleMap);
            last;
        }
    }
    emitChanges($update, $acl, { $objectType.'Name' => $objectName });
};


#-------------------------------------------------------------------------
# applyRule
#
#       Apply all rule acl entries to the specified acl, performing any
#       needed role lookups.
#-------------------------------------------------------------------------
sub applyRule {
    my ($acl, $rule, $roleMap) = @_;

    foreach my $entry (@{$rule}) {
        my @keys;
        my ($type, $name);
        if (exists $entry->{group}) {
            push @keys, 'group:' . $entry->{group};
        } elsif (exists $entry->{project}) {
            push @keys, 'user:project: ' . $entry->{project};
        } elsif (exists $entry->{user}) {
            push @keys, 'user:' . $entry->{user};
        } elsif (exists $entry->{role}) {
            @keys = map { 'group:'.$_ } @{$roleMap->{$entry->{role}}};
        } else {
            die "ERROR: ACE without principal type\n\t".encode_json($entry)."\n";
        }
        $acl->{modified}{$_} = $entry->{access} foreach @keys;
    }
}

#-------------------------------------------------------------------------
# emitChanges
#
#       Emit api requests to effect any changes that need to be made to
#       the given acl.
#-------------------------------------------------------------------------
sub emitChanges {
    my ($batch, $acl, $loc) = @_;

    # First add the new ACEs.  If an entry already exists, modify it.
    # Otherwise, create it.
    foreach my $key (keys %{$acl->{modified}}) {
        my $privs = $acl->{modified}{$key};
        if ($privs) {
            my ($type, $name) = split(':',$key,2);
            my $cmd = exists $acl->{origKeys}->{$key}
            ? 'modifyAclEntry' : 'createAclEntry';
            my @privs = @{$privs};
            my %opts = (
                readPrivilege => $privs[0],
                modifyPrivilege => $privs[1],
                executePrivilege => $privs[2],
                changePermissionsPrivilege => $privs[3],
            );
            while (my ($k, $v) = each(%{$loc})) {
                $opts{$k} = $v;
            }
            $batch->$cmd($type, $name, \%opts);
            delete $acl->{modified}{$key};
        }
    }

    # Now delete any entries marked for deletion
    foreach my $key (keys %{$acl->{modified}}) {
        $batch->deleteAclEntry(split(':',$key,2), $loc);
    }
}

#-------------------------------------------------------------------------
# checkCreate
#
#       Returns true if any of the specified groups is authorized to
#       create the specifed type of object by any team.
#-------------------------------------------------------------------------

sub checkCreate {
    my ($self, $objectType, $teamName, $groups) = @_;

    my %groups = map { $_, 1 } @{$groups};
    my $team = $self->{policy}->{teams}->{$teamName};
    if (!$team) {
        die "Unknown team '$teamName'\n";
    }

    while (my ($roleName, $role) = each %{$team->{roles}}) {
        my $createTypes = $role->{create};
        next unless ($createTypes);
        foreach (@{$createTypes}) {
            if ($_ eq $objectType && exists $groups{$role->{group}}) {
                return 1;
            }
        }
    }
    return 0;
}

#-------------------------------------------------------------------------
# apply
#
#       Applies the policy to all objects in the system.
#-------------------------------------------------------------------------

sub apply {
    my ($self, $update) = @_;
    foreach my $objType (@allObjTypes) {
        my $handler = "handle".ucfirst($objType);
        my $rules = $self->{$objType};
        {
            no strict 'refs';
            &$handler($self, $update, $rules);
        }
    }
}


#-------------------------------------------------------------------------
# loadAcl
#
#       Reads the entries for an acl from a getAccess response.
#-------------------------------------------------------------------------
sub loadAcl
{
    my ($response) = @_;
    my $acls = $response->{object};
    return unless $acls;
    my $acl = {};
    foreach my $entry (@{$acls->[0]->{aclEntry}}) {
        my $key = $entry->{principalType} . ':' . $entry->{principalName};
        my @privs = map { $entry->{$_.'Privilege'} }
        qw(read modify execute changePermissions);
        $acl->{aces}{$key} = \@privs;
        $acl->{origKeys}{$key} = 1;
    }
    return $acl;
}

#-------------------------------------------------------------------------
# clearAcl
#
#       Removes acl entries for any managed users or groups from the
#       specified acl.
#-------------------------------------------------------------------------
sub clearAcl
{
    my ($self, $acl) = @_;
    foreach (keys %{$self->{managedGroups}}) {
       my $key = "group:".$_;
        if (exists $acl->{aces}{$key}) {
           $acl->{modified}{$key} = undef;
        }
    }
    foreach (keys %{$self->{managedUsers}}) {
      my $key = "user:".$_;
        if (exists $acl->{aces}{$key}) {
         $acl->{modified}{$key} = undef;
        }
    }
}

#-------------------------------------------------------------------------
# handleSystemObject
#
#       Policy handler for 'systemObject' rules.
#-------------------------------------------------------------------------
sub handleSystemObject
{
    my ($self, $update, $rules) = @_;
    my $batch = $self->{cmdr}->newBatch();

    my @objNames = keys %{$rules};
    my @reqs;
    foreach my $objName (@objNames) {
        push @reqs, $batch->getAccess({ systemObjectName => $objName });
    }
    $batch->submit();

    my $roleMap = $self->{roleMap}->{global};

    foreach my $objName (@objNames) {
        my $acl = loadAcl($batch->find(shift @reqs));
        next unless $acl;
        $self->clearAcl($acl);
        applyRule($acl, $rules->{$objName}, $roleMap);
        emitChanges($update, $acl, {systemObjectName => $objName});
    }
}

#-------------------------------------------------------------------------
# handlePlugin
#
#       Policy handler for 'plugin' rules.  This handler applies to
#       plugin projects.
#-------------------------------------------------------------------------
sub handlePlugin
{
    my ($self, $update, $rules) = @_;
    my $result = $self->{cmdr}->getPlugins();

    my @projects = $result->findnodes("//projectName");
    $self->doHandleObjects('project', $update, $rules, @projects);
}

#-------------------------------------------------------------------------
# handleProject
#
#       Policy handler for 'project' rules.  This handler applies to
#       non-plugin projects.
#-------------------------------------------------------------------------
sub handleProject
{
    my ($self, $update, $rules) = @_;
    my $result = $self->{cmdr}->findObjects('project', {
        filter => [{propertyName => 'pluginName', operator => 'isNull'}]
    });

    my @projects = $result->findnodes("//projectName");

    $self->doHandleObjects('project', $update, $rules, @projects);
}

#-------------------------------------------------------------------------
# handleArtifact
#
#       Policy handler for 'artifact' rules.
#-------------------------------------------------------------------------
sub handleArtifact
{
    my ($self, $update, $rules) = @_;
    my $result = $self->{cmdr}->getArtifacts();

    my @artifacts = $result->findnodes("//artifactName");
    $self->doHandleObjects('artifact', $update, $rules, @artifacts);
}

#-------------------------------------------------------------------------
# handleEmailConfig
#
#       Policy handler for 'emailConfig' rules.
#-------------------------------------------------------------------------
sub handleEmailConfig
{
    my ($self, $update, $rules) = @_;
    my $result = $self->{cmdr}->getEmailConfigs();

    my @emailConfigs = $result->findnodes("//configName");
    $self->doHandleObjects('emailConfig', $update, $rules, @emailConfigs);
}

#-------------------------------------------------------------------------
# handleRepository
#
#       Policy handler for 'repository' rules.
#-------------------------------------------------------------------------
sub handleRepository
{
    my ($self, $update, $rules) = @_;
    my $result = $self->{cmdr}->getRepositories();

    my @repositories = $result->findnodes("//repositoryName");
    $self->doHandleObjects('repository', $update, $rules, @repositories);
}

#-------------------------------------------------------------------------
# handleResource
#
#       Policy handler for 'resource' rules.
#-------------------------------------------------------------------------
sub handleResource
{
    my ($self, $update, $rules) = @_;
    my $result = $self->{cmdr}->getResources();

    my @resources = $result->findnodes("//resourceName");
    $self->doHandleObjects('resource', $update, $rules, @resources);
}

#-------------------------------------------------------------------------
# handleWorkspace
#
#       Policy handler for 'workspace' rules.
#-------------------------------------------------------------------------
sub handleWorkspace
{
    my ($self, $update, $rules) = @_;
    my $result = $self->{cmdr}->getWorkspaces();

    my @workspaces =$result->findnodes("//workspaceName");
    $self->doHandleObjects('workspace', $update, $rules, @workspaces);
}

#-------------------------------------------------------------------------
# handleZone
#
#       Policy handler for 'zone' rules.
#-------------------------------------------------------------------------
sub handleZone
{
    my ($self, $update, $rules) = @_;
    my $result = $self->{cmdr}->getZones();

    my @zones = $result->findnodes("//zoneName");
    $self->doHandleObjects('zone', $update, $rules, @zones);
}

#-------------------------------------------------------------------------
# handleGateway
#
#       Policy handler for 'gateway' rules.
#-------------------------------------------------------------------------
sub handleGateway
{
    my ($self, $update, $rules) = @_;
    my $result = $self->{cmdr}->getGateways();

    my @gateways = $result->findnodes("//gatewayName");
    $self->doHandleObjects('gateway', $update, $rules, @gateways);
}

#-------------------------------------------------------------------------
# doHandleObjects
#
#       Implements a generic handler for any type of top-level object.
#-------------------------------------------------------------------------
sub doHandleObjects
{
    my $self = shift;
    my $type = shift;
    my $update = shift;
    my $rules = shift;

    # Find all objects that match at least one rule
    my @names = grep {
        my $name = $_;
        my $found = 0;
        foreach my $rule (@{$rules}) {
            if ($name =~ $rule->{pattern}) {
               $found = 1;
               last;
            }
        }
        $found;
    } @_;
    return unless @names;

    if ($type eq 'plugin') {
        $type = 'project';
        @names = map { "/plugins/$_/project" } @names;
    }
    my $loc = $type . "Name";

    # Fetch access information about the matching objects
    my $batch = $self->{cmdr}->newBatch('single');
    my @reqs = map { $batch->getAccess({$loc => $_}); } @names;
    $batch->submit();

    foreach my $name (@names) {
        # Set up any special roles associated with this object
        my $roleMap =  $self->{roleMap}->{$type}->{$name};

        my $acl = loadAcl($batch->find(shift @reqs));
        next unless $acl;
        $self->clearAcl($acl);

        # Apply the first rule that matches
        foreach my $rule (@{$rules}) {
            if ($name =~ $rule->{pattern}) {
                applyRule($acl, $rule->{acl}, $roleMap);
                last;
            }
        }
        emitChanges($update, $acl, {$loc => $name});
    }
}

#-------------------------------------------------------------------------
# handlePropertySheet
#
#       Policy handler for 'propertySheet' rules.
#-------------------------------------------------------------------------
sub handlePropertySheet
{
    my ($self, $update, $rules) = @_;

    # Look up sheet ids for specified property sheets
    my $batch = $self->{cmdr}->newBatch('single');

    my @reqs = map {
        $batch->expandString(q{$[}.$_->{path}."/propertySheetId]");
    } @{$rules};
    $batch->submit();
    my @sheets = map { $batch->findvalue($_,'value')} @reqs;

    # Now look up acls for each sheet
    $batch = $self->{cmdr}->newBatch('single');
    @reqs = map { $batch->getAccess({ propertySheetId => $_ }) } @sheets;
    $batch->submit();

    my $roleMap = $self->{roleMap}->{global};
    # Apply rules to acls
    foreach my $rule (@{$rules}) {
        my $id = shift @sheets;
        my $acl = loadAcl($batch->find(shift @reqs));
        next unless $acl;
        $self->clearAcl($acl);
        applyRule($acl, $rule->{acl}, $roleMap);
        emitChanges($update, $acl, {propertySheetId => $id});
    }
}

#-------------------------------------------------------------------------
# isTeamObjType
#
#       Returns true if the specified type can be associated with a team.
#-------------------------------------------------------------------------

sub isTeamObjType {
    my $type = shift;
    return grep {$type eq $_} @teamObjTypes;
}

1;
