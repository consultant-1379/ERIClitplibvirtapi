from litp.migration import BaseMigration
from litp.migration.operations import AddCollection


class Migration(BaseMigration):
    version = '1.22.3'
    operations = [AddCollection('vm-service', 'vm_disks', 'vm-disk')]
