from litp.migration import BaseMigration
from litp.migration.operations import AddCollection


class Migration(BaseMigration):
    version = '1.34.1'
    operations = [AddCollection('vm-service', 'vm_zypper_repos',
                                'vm-zypper-repo')
                  ]