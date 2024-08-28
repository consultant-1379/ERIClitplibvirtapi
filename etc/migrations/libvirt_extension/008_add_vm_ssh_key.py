from litp.migration import BaseMigration
from litp.migration.operations import AddCollection


class Migration(BaseMigration):
    version = '1.12.4'
    operations = [AddCollection('vm-service', 'vm_ssh_keys', 'vm-ssh-key')]
