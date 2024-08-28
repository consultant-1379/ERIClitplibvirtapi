from litp.migration import BaseMigration
from litp.migration.operations import AddCollection


class Migration(BaseMigration):
    version = '1.10.20'
    operations = [AddCollection('vm-service', 'vm_nfs_mounts', 'vm-nfs-mount')]
