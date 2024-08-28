from litp.migration import BaseMigration
from litp.migration.operations import AddProperty


class Migration(BaseMigration):
    version = '1.32.2'
    operations = [  AddProperty('vm-firewall-rule', 'proto', 'tcp'),
                    AddProperty('vm-firewall-rule', 'dport', '22') ]
