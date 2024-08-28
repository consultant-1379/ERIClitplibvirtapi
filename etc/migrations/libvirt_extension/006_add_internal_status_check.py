from litp.migration import BaseMigration
from litp.migration.operations import AddProperty


class Migration(BaseMigration):
    version = '1.10.14'
    operations = [AddProperty('vm-service', 'internal_status_check', 'on')]
