from litp.migration import BaseMigration
from litp.migration.operations import AddProperty


class Migration(BaseMigration):
    version = '1.10.12'
    operations = [AddProperty('vm-service', 'adaptor_version', '')]
