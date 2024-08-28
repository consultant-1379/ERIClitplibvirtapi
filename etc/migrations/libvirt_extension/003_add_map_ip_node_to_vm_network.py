from litp.migration import BaseMigration
from litp.migration.operations import AddProperty


class Migration(BaseMigration):
    version = '1.10.11'
    operations = [AddProperty('vm-network-interface', 'node_ip_map', '{}')]
