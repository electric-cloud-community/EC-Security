@files = (
    ['//property[propertyName="ec_setup"]/value', 'ec_setup.pl'],
    ['//property[propertyName="scripts"]//property[propertyName="promoteHook"]/value', 'promoteHook.pl'],
    ['//property[propertyName="scripts"]//property[propertyName="apply.pm"]/value', 'lib/apply.pm'],
    ['//property[propertyName="scripts"]//property[propertyName="cleanup.pm"]/value', 'lib/cleanup.pm'],
    ['//property[propertyName="scripts"]//property[propertyName="factory.pm"]/value', 'lib/factory.pm'],
    ['//property[propertyName="scripts"]//property[propertyName="policy.pm"]/value', 'lib/policy.pm'],
    ['//property[propertyName="ECPolicies"]//property[propertyName="basic"]/value', 'basicPolicy.json'],
    ['//property[propertyName="ECPolicies"]//property[propertyName="initial"]/value', 'initialPolicy.json'],
    ['//property[propertyName="ECPolicies"]//property[propertyName="sampleTeam"]/value', 'teamPolicy.json'],
);
