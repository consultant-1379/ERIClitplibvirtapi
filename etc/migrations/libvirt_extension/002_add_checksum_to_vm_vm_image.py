from litp.migration import BaseMigration
from litp.migration.operations import AddProperty


class Migration(BaseMigration):
    version = '1.10.1'
    operations = [AddProperty('vm-image', 'checksum', '')]
