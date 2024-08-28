from litp.migration import BaseMigration
from litp.migration.operations import AddProperty


class Migration(BaseMigration):
    version = '1.16.2'
    operations = [ AddProperty('vm-service', 'node_hostname_map', '{}'), ]
