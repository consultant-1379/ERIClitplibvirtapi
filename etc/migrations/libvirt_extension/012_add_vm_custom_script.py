from litp.migration import BaseMigration
from litp.migration.operations import AddCollection


class Migration(BaseMigration):
    version = '1.27.3'
    operations = [AddCollection('vm-service', 'vm_custom_script',
                                'vm-custom-script')]
