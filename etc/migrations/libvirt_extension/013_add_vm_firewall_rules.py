from litp.migration import BaseMigration
from litp.migration.operations import AddCollection


class Migration(BaseMigration):
    version = '1.30.1'
    operations = [AddCollection('vm-service', 'vm_firewall_rules', 'vm-firewall-rule')]
