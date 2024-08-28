from litp.migration import BaseMigration
from litp.migration.operations import AddCollection


class Migration(BaseMigration):
    version = '1.24.2'
    operations = [AddCollection('vm-service', 'vm_ram_mounts', 'vm-ram-mount')]
