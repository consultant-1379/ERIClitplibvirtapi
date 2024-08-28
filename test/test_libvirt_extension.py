##############################################################################
# COPYRIGHT Ericsson AB 2013
#
# The copyright to the computer program(s) herein is the property of
# Ericsson AB. The programs may be used and/or copied only with written
# permission from Ericsson AB. or in accordance with the terms and
# conditions stipulated in the agreement/contract under which the
# program(s) have been supplied.
##############################################################################

import time
import unittest

import mock

from libvirt_extension.libvirt_extension import (LibvirtExtension,
                                                 MBRangeValidator,
                                                 IP46DHCPValidator,
                                                 DevicePathValidator,
                                                 MACAddressPrefixValidator,
                                                 SSHKeyValidator,
                                                 StaticOrDynamicIPValidator,
                                                 DuplicateEntriesValidator,
                                                 IPv6AndMaskListValidator,
                                                 Gateway6Validator,
                                                 MaxCustomScriptsValidator,
                                                 IPV6_NOT_IN_THE_SAME_SUBNET,
                                                 GWV6_AND_IPV6_NOT_IN_THE_SAME_SUBNET,
                                                 IPV6_IS_MULTICAST,
                                                 IPV6_IS_RESERVED,
                                                 IPV6_IS_LOCAL_LINK,
                                                 IPV6_IS_LOOP_BACK,
                                                 IPV6_IS_NOT_VALID,
                                                 CpuSetValidator,
                                                 PositiveIntegerListValidator,
                                                 SourceProviderValidator,
                                                 SubnetValidator,
                                                 VmPortRangeValidator)
from litp.core.exceptions import ViewError
from litp.core.model_manager import ModelManager
from litp.core.validators import ValidationError
from litp.extensions.core_extension import CoreExtension


class TestLibvirtExtension(unittest.TestCase):

    def setUp(self):
        self.model_manager = ModelManager()
        self.validator = self.model_manager.validator
        self.ext = LibvirtExtension()

        self.prop_types = dict()
        for prop_type in self.ext.define_property_types():
            self.prop_types[prop_type.property_type_id] = prop_type

    def test_property_types_registered(self):
        expected_property_types = ['libvirt_ram_size', 'libvirt_url',
                                   'vm_repo_name', 'internal_status_check',
                                   'checksum_string', 'nfs_mount_options',
                                   'device_path', 'libvirt_device_name',
                                   'libvirt_ssh_key',
                                   'comma_separated_vm_hostnames',
                                   'libvirt_ipv6_gateway_address',
                                   'ram_mount_type', 'cpuset_range',
                                   'positive_integer_list',
                                   'ram_mount_options',
                                   'comma_separated_scripts',
                                   'vm_firewall_rule_name',
                                   'vm_firewall_rule_action',
                                   'vm_firewall_rule_ip_subnet',
                                   'vm_firewall_rule_provider',
                                   'vm_firewall_rule_protocol',
                                   'vm_firewall_rule_port']
        actual_property_types = [pt.property_type_id for pt in
                                 self.ext.define_property_types()]
        self.assertEquals(expected_property_types, actual_property_types)

    def test_item_types_registered(self):
        expected_item_types = ['libvirt-provider', 'libvirt-system',
                               'vm-service', 'vm-image', 'vm-yum-repo',
                               'vm-zypper-repo', 'vm-package',
                               'vm-network-interface', 'vm-alias',
                               'vm-nfs-mount', 'vm-disk', 'vm-ssh-key',
                               'vm-ram-mount', 'vm-custom-script',
                               'vm-firewall-rule']
        actual_item_types = [it.item_type_id for it in
                             self.ext.define_item_types()]
        self.assertEquals(expected_item_types, actual_item_types)

    def test_get_filesystem_item(self):
        fs = mock.Mock(item_id='fs1')
        file_systems_list = mock.MagicMock()
        file_systems_list.__iter__ = mock.Mock(return_value=iter([fs]))

        vg = mock.MagicMock()
        vg.file_systems = file_systems_list
        storageProfile = mock.MagicMock()
        storageProfile.query.return_value = [vg]

        api = mock.MagicMock()
        api.query_by_vpath.return_value = storageProfile

        vm_disk_item = mock.Mock(host_file_system='fs1')
        self.assertEqual(
            self.ext.get_filesystem_item(api, vm_disk_item), fs)

        fs = mock.Mock()
        self.assertRaises(ViewError, self.ext.get_filesystem_item, api,
            vm_disk_item)

        vm_disk_item = mock.Mock(host_file_system='fs2')
        self.assertRaises(ViewError, self.ext.get_filesystem_item, api,
            vm_disk_item)

    def test_script_name_regex(self):
        self.assertTrue('comma_separated_scripts' in self.prop_types)

        css = self.prop_types['comma_separated_scripts']

        for value in ['Xy+', '@', '$', 's]']:
            errors = self.validator._run_property_type_validators(css, 'comma_separated_scripts', value)
            error_message = ("Invalid value '{0}'. Value can only contain "
                            "numbers 0-9, upper or lower case letters A-Z, "
                            "hyphens, underscores and full stops and can be "
                            "no longer than 31 characters".format(value))
            expected = ValidationError(property_name='comma_separated_scripts',
                                       error_message=error_message)
            self.assertEquals([expected], errors)

        for value in ['abc', 'xyz', 'Abc', 'xy3', 'd_f', '1-d', '1_3']:
            for ext in ['.py', '.sh']:
                file_name = ''.join([value + ext])
                errors = self.validator._run_property_type_validators(css, 'comma_separated_scripts', file_name)
                self.assertEquals([], errors)

        for value in ['abc.py,xyz.sh,__', 'Abc,xy3.sh,d_f.py']:
            errors = self.validator._run_property_type_validators(css, 'comma_separated_scripts', value)
            self.assertEquals([], errors)

    def test_cpuset_validation(self):
        cpuset_range = self.prop_types['cpuset_range']

        test_data = [
            ('0', False),
            ('0-1', False),
            ('0-1,3-4', False),
            ('0-1,6,7', False),
            ('0,1,6-8', False),
            ('0,1,6,8', False),
            ('0-1,6,8-10', False),
            ('0,6-9,11', False),
            ('4,2-6', False),
            ('2-6,4', False),
            ('4-4', False),
            ('a', True),
            ('abc', True),
            ('a,b,c', True),
            ('0-A', True),
            ('0--6', True),
            ('', True),
            (',', True),
            ('-', True),
            ('1,b,2', True),
            ('-1', True),
            ('1-', True),
            ('2,3,-6', True),
            ('2,-3,6', True),
            ('-2,3,6', True),
            ('6-4', True),
        ]

        for data in test_data:
            test_value = data[0]
            expect_error = data[1]
            actual_errors = self.validator._run_property_type_validators(
                    cpuset_range, 'cpuset', test_value)
            expected_errors = []
            if expect_error:
                error_msg = 'Invalid value \'' + \
                            test_value + '\'. ' + CpuSetValidator.DESC
                expected_errors.append(
                        ValidationError(property_name='cpuset',
                                        error_message=error_msg))
            self.assertEquals(expected_errors, actual_errors)

    def test_positive_integer_list_validation(self):
        numeric_list = self.prop_types['positive_integer_list']
        test_data = [
            ('0', False),
            ('1', False),
            ('-1', True, '-1'),
            ('a', True, 'a'),
            ('9,10', False),
            ('-9,10', True, '-9'),
            ('0-1', True, '0-1')
        ]
        prop_name = 'cpunodeset'
        for data in test_data:
            test_value = data[0]
            expect_error = data[1]
            actual_errors = self.validator._run_property_type_validators(
                    numeric_list, prop_name, test_value)
            expected_errors = []
            if expect_error:

                error_msg = 'Invalid value \'' + data[2] + '\'. ' + \
                            PositiveIntegerListValidator.DESC
                expected_errors.append(
                        ValidationError(property_name=prop_name,
                                        error_message=error_msg))
            self.assertEquals(expected_errors, actual_errors)


class TestIP46DHCPValidator(unittest.TestCase):

    def test_wrong_ipv4(self):
        validator = IP46DHCPValidator()
        error = validator.validate({"ipaddresses": "10.10.10.10.10"})
        self.assertEquals("Invalid IPAddress value '10.10.10.10.10'", error.error_message)

    def test_wrong_ipv6(self):
        validator = IP46DHCPValidator()
        error = validator.validate({"ipaddresses": "2607:f0d0:1002:51:1"})
        self.assertEquals("Invalid IPAddress value '2607:f0d0:1002:51:1'", error.error_message)

    def test_mixed_ipv4_ipv6(self):
        validator = IP46DHCPValidator()
        error = validator.validate({"ipaddresses": "10.10.10.10.1, 2607:f0d0:1002:51:4"})
        self.assertEquals("Invalid IPAddress value '10.10.10.10.1'", error.error_message)

    def test_valid_list(self):
        validator = IP46DHCPValidator()
        error = validator.validate({"ipaddresses": "10.10.10.10, 2607:f0d0:1002:51::4, 10.10.10.11"})
        self.assertEquals(None, error)

    def test_invalid_list_dhcp(self):
        validator = IP46DHCPValidator()
        error = validator.validate({"ipaddresses": "10.10.10.10,2607:f0d0:1002:51::4,dhcp"})
        self.assertEquals(None, error)

    def test_valid_list_dhcp(self):
        validator = IP46DHCPValidator()
        error = validator.validate({"ipaddresses": "dhcp"})
        self.assertEquals(None, error)


class TestMBRangeValidator(unittest.TestCase):

    def test_wrong_parameter(self):
        validator = MBRangeValidator("32M")
        value = "32G"
        self.assertTrue(isinstance(validator.validate(value), ValidationError))

    def test_min_range_pass(self):
        validator = MBRangeValidator("32M")
        value = "32M"
        self.assertEquals(None, validator.validate(value))

    def test_max_range_pass(self):
        validator = MBRangeValidator("2024M")
        value = "2024M"
        self.assertEquals(None, validator.validate(value))

    def test_min_max_range_pass(self):
        validator = MBRangeValidator("64M","2024M")
        value = "1024M"
        self.assertEquals(None, validator.validate(value))

    def test_min_range_fail(self):
        validator = MBRangeValidator("32M")
        value = "31M"
        self.assertTrue(isinstance(validator.validate(value), ValidationError))

    def test_max_range_fail(self):
        validator = MBRangeValidator("2025M")
        value = "2024M"
        self.assertTrue(isinstance(validator.validate(value), ValidationError))

    def test_min_max_range_fail(self):
        validator = MBRangeValidator("63M","2024")
        value = "1024M"
        self.assertTrue(isinstance(validator.validate(value), ValidationError))


class TestMountOptionsValidator(unittest.TestCase):

    def setUp(self):
        self.prop_types = dict()
        self.libvirt_ext = LibvirtExtension()
        self.core_ext = CoreExtension()
        for prop_type in self.libvirt_ext.define_property_types():
                self.prop_types[prop_type.property_type_id] = prop_type
        for prop_type in self.core_ext.define_property_types():
                self.prop_types[prop_type.property_type_id] = prop_type

    def assertErrorCount(self, errors, count):
        self.assertEquals(len(errors), count, "%s errors expected, got: %s" % (count, errors))

    def run_all_validators(self, property, property_name, tests):
            for text, error_count in tests:
                errors = self._run_property_type_validators(property, property_name, text)
                self.assertErrorCount(errors, error_count)

    def _run_property_type_validators(self, property_type,
                                      property_name, property_value):
            errors = []
            for validator in property_type.validators:
                before = time.time()
                err = validator.validate(property_value)
                after = time.time()
                if err:
                    err.property_name = property_name
                    errors.append(err)
                # Ensure each validator takes less than 1 second
                self.assertTrue(after - before < 1.0)
            return errors

    def test_valid_path_string(self):
        self.assertTrue('path_string' in self.prop_types)
        mountpoint_pt = self.prop_types['path_string']

        tests = [
            ('foo', 1),
            ('_foo bar', 1),
            ('/var', 0),
            ('/var/log/ltp', 0),
            ('/opt/va_ree', 0)
        ]
        self.run_all_validators(mountpoint_pt, "path_string", tests)

    def test_valid_mount_options(self):
        self.assertTrue('nfs_mount_options' in self.prop_types)
        mount_options = self.prop_types['nfs_mount_options']
        tests = [
            (' ', 2),
            (',', 2),
            ('foobar', 1),
            ('hard,,', 2),
            ('hard,soft', 1),
            ('ac,noac', 1),
            ('bg,fg', 1),
            ('sharecache,nosharecache', 1),
            ('resport,noresport', 1),
            ('cto,nocto', 1),
            ('intr,nointr', 1),
            ('rsize=1024,rsize=1024', 1),
            ('soft,timeo=AA', 2),
            ('lookupcache=rubbish', 1),
            ('proto=rubbish', 1),
            ('sec=rubbish', 1),
            ('clientaddr=rubbish', 1),
            ('rubbish=rubbish', 1),
            ('timeo=AA', 2),
            ('soft', 0),
            ('soft,timeo=100', 0),
            ('actimeo=100,retrans=5,rsize=1024', 0),
            ('acregmin=5,acregmax=9', 0),
            ('port=9999', 0),
            ('lookupcache=all', 0),
            ('clientaddr=109.109.109.109', 0),
            ('clientaddr=2001:cdba::3257:9652', 0),
            ('sec=sys', 0),
            ('retry=5', 0),
            ('acdirmin=60', 0),
            ('retrans=5', 0),
            ('rsize=1024', 0),
            ('wsize=2048', 0),
            ('proto=tcp', 0),
            ('defaults', 0),
            ('acdirmin=5,acdirmax=12', 0),
            ('minorversion=3', 0),
            ('acregmin=5,acregmax=12', 0),
            ('async,sync', 1),
            ('resvport,noresvport', 1),
            ('nointr', 0),
            ('atime,noatime', 1),
            ('auto,noauto', 1),
            ('auto', 0),
            ('dev,nodev', 1),
            ('diratime,nodiratime', 1),
            ('dirsync', 0),
            ('exec,noexec', 1),
            ('group', 0),
            ('iversion,noiversion', 1),
            ('mand,nomand', 1),
            ('nofail', 0),
            ('relatime,norelatime', 1),
            ('strictatime,nostrictatime', 1),
            ('suid,nosuid', 1),
            ('remount', 0),
            ('ro,rw', 1),
            ('user,nouser,users', 1),
            ('acl,noacl', 1),
            ('rdirplus,nordirplus', 1),
            ('mountport=8000', 0),
            ('mountproto=tcp', 0),
            ('mounthost=testhost', 0),
            ('mountvers=2.0', 0),
            ('namlen=30', 0),
            ('nfsvers=3.1.1', 0),
            ('vers=3.0', 0),
            ('local_lock=yes', 0),
            ('_netdev="test', 0),
            ("rsize=1024,noexec,nodev,nosuid,adding_in_some_nonsense_part_^^^^^^^", 2)
            ]

        self.run_all_validators(mount_options, 'nfs_mount_options', tests)

    def test_ram_mount_mount_options_regex(self):
        self.assertTrue('ram_mount_options' in self.prop_types)
        mount_options = self.prop_types['ram_mount_options']

        tests = [
            (' ', 1),
            (',', 1),
            ('foobar', 0),
            ('foo,bar', 0),
            ('foo, bar', 1),
            ("size=512M", 0),
            ("size=512M,nodev,nosuid,noexec", 0),
            ("size=512M,nodev,nosuid,noexec,any,thing,at,all", 0),
            ("size=512M,nodev,nosuid,noexec,consecutive,commas,,", 1),
            ("size=512M,noexec,nodev,nosuid,adding_in_some_nonsense_part_^^^^^^^", 1)
                ]

        self.run_all_validators(mount_options, 'ram_mount_options', tests)

class TestDuplicateEntriesValidator(unittest.TestCase):

    def test_validator_success(self):
        property_value = 'vm1,vm2'
        errors = DuplicateEntriesValidator().validate(property_value)
        self.assertEquals('None', str(errors))

        property_value = 'abc.py,123.sh'
        errors = DuplicateEntriesValidator().validate(property_value)
        self.assertEquals('None', str(errors))

    def test_validator_empty(self):
        property_value = ''
        errors = DuplicateEntriesValidator().validate(property_value)
        self.assertEquals('None', str(errors))

    def test_validator_hostnames_duplicates(self):
        property_value = 'vm1,vm1'
        errors = DuplicateEntriesValidator().validate(property_value)
        self.assertEquals('<None - ValidationError - Invalid value: vm1,vm1. In this property the following values have been specified more than once: vm1>', str(errors))

    def test_validator_multi_hostnames_multi_duplicates(self):
        property_value = 'vm1,vm1,vm2,vm2'
        errors = DuplicateEntriesValidator().validate(property_value)
        self.assertEquals('<None - ValidationError - Invalid value: vm1,vm1,vm2,vm2. In this property the following values have been specified more than once: vm2, vm1>', str(errors))

    def test_validator_custom_scripts_success_same_name_diff_ext(self):
        property_value = 'abc.py,abc.sh'
        errors = DuplicateEntriesValidator().validate(property_value)
        self.assertEquals('None', str(errors))

class TestMaxCustomScriptsValidator(unittest.TestCase):

    def test_validator_pre_max(self):
        property_value ='abc.py,abc.sh'
        errors = MaxCustomScriptsValidator().validate(property_value)
        self.assertEquals('None', str(errors))

    def test_validator_post_max(self):
        property_value = 'abc.py,abc.sh,def.py,xyz.sh,xyz.py,def.sh'
        errors = MaxCustomScriptsValidator().validate(property_value)
        self.assertEquals('<None - ValidationError - Max number of scripts allowed is 5>', str(errors))

class TestDevicePathValidator(unittest.TestCase):

    def test_valid_device_path_name_with_hostname(self):
        validator = DevicePathValidator()
        self.assertEquals(None, validator.validate("ms1:/mnt/data"))

    def test_valid_device_path_name_with_hostname2(self):
        validator = DevicePathValidator()
        self.assertEquals(None, validator.validate("http://192.168.0.42:/"
                                                   "exports/mount_3"))

    def test_valid_device_path_name_with_fqdn_hostname(self):
        validator = DevicePathValidator()
        self.assertEquals(None, validator.validate("hostname.fqdn.com:"
                                            "/192.168.0.42:/exports/mount_3"))

    def test_invalid_device_path_name_with_fqdn_hostname(self):
        validator = DevicePathValidator()
        self.assertTrue(isinstance(validator.validate("hostname.-fqdn.com:"
                                            "/192.168.0.42:/exports/mount_3"),
                                            ValidationError))

    def test_valid_device_path_name_with_ipv4(self):
        validator = DevicePathValidator()
        self.assertEquals(None, validator.validate("10.10.11.100:/mnt/data"))

    def test_invalid_ipv4_for_device_path(self):
        validator = DevicePathValidator()
        self.assertTrue(isinstance(validator.validate("10.10-.1.100:/mnt/data")
                                            , ValidationError))

    def test_invalid_device_path(self):
        validator = DevicePathValidator()
        self.assertTrue(isinstance(validator.validate("10.10.11.100/mnt/data"), ValidationError))

    def test_invalid_device_path_contains_nohostname(self):
        validator = DevicePathValidator()
        self.assertTrue(isinstance(validator.validate(":/mnt/data"), ValidationError))

    def test_invalid_device_path_contains_no_string_after_colon(self):
        validator = DevicePathValidator()
        self.assertTrue(isinstance(validator.validate("hostname:/"), ValidationError))

    def test_invalid_device_path_name_contains_whitespace(self):
        validator = DevicePathValidator()
        self.assertTrue(isinstance(validator.validate("http://192.168.0.42: /"
                                                   "exports/mount_3"),
                                            ValidationError))

    def test_invalid_device_path_name_with_valid_fqdn(self):
        validator = DevicePathValidator()
        self.assertTrue(isinstance(validator.validate("hostname.fqdn.com:"
                                            "/192.168.0.42:/exports/mount_3,"),
                                            ValidationError))

    def test_invalid_device_path_name_with_valid_hostname(self):
        validator = DevicePathValidator()
        self.assertTrue(isinstance(validator.validate("ms1:/mnt/data,"),
                                            ValidationError))

class TestMACAddressPrefixValidator(unittest.TestCase):

    def test_invalid_mac_prefix(self):
        validator = MACAddressPrefixValidator()
        properties = {"mac_prefix": "BB:CC:DD"}
        expected_error = ('<None - ValidationError - "mac_prefix" should contain a valid virtual machine mac prefix.'
            ' This means that the second digit of the first octet must be one of four options: "2", "6", "A" or "E".'
            ' For example: "52:55:55">')
        self.assertEquals(expected_error, str(validator.validate(properties)))


class TestSSHKeyValidator(unittest.TestCase):

    def test_short_rsa_key(self):
        validator = SSHKeyValidator()
        rsa_2047_key = ("ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQBfwBYsNfEVRQBI3HdH"
                        "A3LoCoGi9trx+qM5h0dv9eNtdFDM7WPwSRodyUy6iXuyUR/PJckM"
                        "F+YEte8RucCKBsDuPVxvVoKtH/5kg0Bk+/ZBFhjxRLlwyxzmkYIE"
                        "tpjRZSx6Hh9eGG3WaIS8cq5ofBq3/VEeLS33SzZwz3i7v65pAsYS"
                        "EvD3K69k44fPii6hn5Wr4IaiZu1F/01vTggqIvSEUztaDQo2B8QQ"
                        "ZrLgZnFT44W8dAKUN3sR7+2zgrTr3MQv1OvIo0RjSBNUv1kZBGNv"
                        "3HrRzqRj1T+6CqH4iCovGhlVZatXkh2fByvPWyN3TlY625RJRhF/"
                        "c6qtZGhi7mmR root@rh6-ms1")
        error = validator.validate(rsa_2047_key)
        self.assertTrue(isinstance(error, ValidationError))

    def test_valid_rsa_key(self):
        validator = SSHKeyValidator()
        rsa_2048_key = ("ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEA4f43uRmGB0txtP4i"
                        "PIVK0u8N5ZxE2qeh3jzS2d9d/EdeFN6rTOFIxUk0LhD6XyARu01/"
                        "3IN2yfrxINvMLV+QQddIvghomfYnRPlEsTlPUgk+5lIoG74XeUIQ"
                        "FfwyJYzSaSVJvGoqadNTmthVIH5EjYyrzBQPWdm3Er0KWGlZ3pBJ"
                        "yOHtjpGDx4Vlvvzd+EEbBTAGCKidNE71Qb4VpaOWJkguSTc/sZDF"
                        "bV1kv0XrcLWNl4STbQArfQd58DcXRFPO1p58lF31xhKRf6hjQ+Qj"
                        "ohwR9mYtW4Q5nW/AymZUkLCiL4B3SwAUSmH5ALCqHa9RQPJypsLv"
                        "GgnlWfipmko4vw== root@rh6-ms1")
        error = validator.validate(rsa_2048_key)
        self.assertEquals(None, error)

    def test_wrong_type_key(self):
        validator = SSHKeyValidator()
        dsa_1024_key = ("ssh-dss AAAAB3NzaC1kc3MAAACBAJ49UEinzWslDORJxYJ9BLO"
                        "mqR9j+aT4AfNtqQZZGvNIGn8vc7pDklKPd7s9bQUip1Nmpru7Zr"
                        "oEHzkmRokivxvLWBz/9kt3XID3zrAmw8MP6ZZ9/VmR8rvys8kyX"
                        "/yFkwMC7uwQEdtK9tBOHRIjmwokwFQoiK49xN51UBIRvULJAAAA"
                        "FQCR3l6gCT5lJ4QDtGuOS3cIgKGqYwAAAIBZa0X8/VIkVIlRygZ"
                        "3CIUeI8Ili4Bj9OW4ujJ25xAwHhQjwrTIdjFoD/fDPRtTdSHdzW"
                        "FtMNPvUSMHxOxsR/BvSZiXuPtWAjZoQtGWsfYNIT65tVLaHTKxN"
                        "RvgqNtrWudnoiVolynM9TY48kB87AmnEnP3a7PulZzK+VLtrB4i"
                        "DAAAAIBtMuUVtauCSLNMOcAsF8EuMvavpXC5LTEdyBQTx0fW/pw"
                        "Ng8rCKeNOFGYmn1SLFTKYJcXvMVc3hgSw1s7LkmPjwr4fBTIKXB"
                        "vrCwkJZCUSW/UAeQLIB5yVPWD1giU0aT9L5FByPEVWtYW8lcV+j"
                        "G9pnrgKJMqpzdcHSo5rH6NYCw== root@rh6-ms1")
        error = validator.validate(dsa_1024_key)
        self.assertTrue(isinstance(error, ValidationError))


    def test_invalid_format_key(self):
        validator = SSHKeyValidator()
        invalid_format = ("invalid AAAAB3NzaC1kc3MAAACBAJ49UEinzWslDORJxYJ9BLO"
                          "mqR9j+aT4AfNtqQZZGvNIGn8vc7pDklKPd7s9bQUip1Nmpru7Zr"
                          "oEHzkmRokivxvLWBz/9kt3XID3zrAmw8MP6ZZ9/VmR8rvys8kyX"
                          "/yFkwMC7uwQEdtK9tBOHRIjmwokwFQoiK49xN51UBIRvULJAAAA"
                          "FQCR3l6gCT5lJ4QDtGuOS3cIgKGqYwAAAIBZa0X8/VIkVIlRygZ"
                          "3CIUeI8Ili4Bj9OW4ujJ25xAwHhQjwrTIdjFoD/fDPRtTdSHdzW"
                          "FtMNPvUSMHxOxsR/BvSZiXuPtWAjZoQtGWsfYNIT65tVLaHTKxN"
                          "RvgqNtrWudnoiVolynM9TY48kB87AmnEnP3a7PulZzK+VLtrB4i"
                          "DAAAAIBtMuUVtauCSLNMOcAsF8EuMvavpXC5LTEdyBQTx0fW/pw"
                          "Ng8rCKeNOFGYmn1SLFTKYJcXvMVc3hgSw1s7LkmPjwr4fBTIKXB"
                          "vrCwkJZCUSW/UAeQLIB5yVPWD1giU0aT9L5FByPEVWtYW8lcV+j"
                          "G9pnrgKJMqpzdcHSo5rH6NYCw== root@rh6-ms1")
        error = validator.validate(invalid_format)
        self.assertTrue(isinstance(error, ValidationError))

    def test_empty_key(self):
        validator = SSHKeyValidator()
        error = validator.validate("")
        self.assertEquals(None, error)


class TestStaticOrDynamicIPValidator(unittest.TestCase):

    def test_valid_dynamic_ip_list(self):
        validator = StaticOrDynamicIPValidator()
        ip_list = "dhcp"
        error = validator.validate({"ipaddresses": ip_list})
        self.assertEquals(error, None)

    def test_valid_static_ip_list(self):
        validator = StaticOrDynamicIPValidator()
        ip_list = "10.10.10.10, 2607:f0d0:1002:51::4"
        error = validator.validate({"ipaddresses": ip_list})
        self.assertEquals(error, None)

    def test_invalid_dynamic_static_ip_list(self):
        validator = StaticOrDynamicIPValidator()
        ip_list = "10.10.10.10, 2607:f0d0:1002:51::4,dhcp"
        error = validator.validate({"ipaddresses": ip_list})
        self.assertEquals(error.error_message, "Invalid list: '%s'. The "
                                               "list can not contain a mix of "
                                               "static and dynamic IP "
                                               "addresses" % ip_list)

class TestIPv6AndMaskListValidator(unittest.TestCase):
    def test_validate_ok(self):
        validator = IPv6AndMaskListValidator()
        ip_list = "2607:f0d0:1002:0011::2,2607:f0d0:1002:0011::3/64"
        gateway6 = "2607:f0d0:1002:0011::1"
        error = validator.validate({"ipv6addresses": ip_list,
                                    "gateway6": gateway6})
        self.assertEquals(error, None)


    def test_validate_ips_not_same_network(self):
        validator = IPv6AndMaskListValidator()
        ip_list = "2607:f0d0:1002:0011::2/64,2607:f0a0:1002:0011::3/64"
        gateway6 = "2607:f0d0:1002:0011::1"
        error = validator.validate({"ipv6addresses": ip_list,
                                    "gateway6": gateway6})
        self.assertEquals(IPV6_NOT_IN_THE_SAME_SUBNET, error.error_message)

    def test_ips_value_is_multicast(self):
        validator = IPv6AndMaskListValidator()
        ip_list = "ff0e:f0d0:1002:7516::2/64"
        error = validator.validate({"ipv6addresses": ip_list})
        self.assertEqual(IPV6_IS_MULTICAST.format(ip_list),
                         error.error_message)

    def test_ips_value_is_reserved(self):
        validator = IPv6AndMaskListValidator()
        ip_list = "a000:0000:0000:0000::2/64"
        error = validator.validate({"ipv6addresses": ip_list})
        self.assertEqual(IPV6_IS_RESERVED.format(ip_list),
                         error.error_message)

    def test_ips_value_is_local_link(self):
        validator = IPv6AndMaskListValidator()
        ip_list = "FE80::/10"
        error = validator.validate({"ipv6addresses": ip_list})
        self.assertEqual(IPV6_IS_LOCAL_LINK.format(ip_list),
                         error.error_message)

    def test_ips_value_is_loop_back(self):
        validator = IPv6AndMaskListValidator()
        ip_list = "0:0:0:0:0:0:0:1/64"
        error = validator.validate({"ipv6addresses": ip_list})
        self.assertEqual(IPV6_IS_LOOP_BACK.format(ip_list),
                         error.error_message)

    def test_ips_value_is_not_valid(self):
        validator = IPv6AndMaskListValidator()
        ip_list = "2607:f0dm:1002:0011::2/64"
        error = validator.validate({"ipv6addresses": ip_list})
        self.assertEqual(IPV6_IS_NOT_VALID.format(ip_list),
                         error.error_message)

    def test_validate_gwt_not_same_network_like_ips(self):
        validator = IPv6AndMaskListValidator()
        ip_list = "2607:f0d0:1002:0011::2/64,2607:f0d0:1002:0011::3/64"
        gateway6 = "2602:f0d0:1002:0011::1"
        error = validator.validate({"ipv6addresses": ip_list,
                                    "gateway6": gateway6})
        self.assertEquals(GWV6_AND_IPV6_NOT_IN_THE_SAME_SUBNET,
                          error.error_message)

    def test_ips_value_are_valid(self):
        validator = IPv6AndMaskListValidator()
        ip_list = "2607:f0d0:1002:0011::2/64,2m07:f0d0:1002:0011::3/64"
        gateway6 = "2602:f0d0:1002:0011::1"
        error = validator.validate({"ipv6addresses": ip_list,
                                    "gateway6": gateway6})
        self.assertEquals(
            error.error_message,
            "IPv6 address '2m07:f0d0:1002:0011::3/64' is not valid")

class TestGateway6Validator(unittest.TestCase):
    def setUp(self):
        self.validator = Gateway6Validator()

    def test_gateway_not_set(self):
        gateway = u""
        self.assertEquals(None, self.validator.validate(gateway))

    def test_mcast(self):
        gateway = 'ffff::1'
        # We shouldn't get a ValidationError from the Route item's validator
        # when the gateway address is malformed because the property validator
        # should have caught that already
        self.assertEquals(
                ValidationError(
                        property_name='gateway',
                        error_message='Cannot use multicast address '
                        'ffff::1 as gateway',
                    ),
                self.validator.validate(gateway)
            )

    def test_loopback(self):
        gateway = '::1'
        self.assertEquals(
                ValidationError(
                        property_name='gateway',
                        error_message='The gateway address ::1 cannot be local loopback.'
                    ),
                self.validator.validate(gateway)
            )

    def test_undefined(self):
        self.assertEquals(
                ValidationError(
                        property_name='gateway',
                        error_message='The gateway address :: cannot be the undefined address.'
                    ),
                self.validator.validate('::')
            )

    def test_link_local(self):
        gateway = 'fe80::1'
        self.assertEquals(
                ValidationError(
                        property_name='gateway',
                        error_message='The gateway address fe80::1 cannot be link-local.'
                    ),
                self.validator.validate(gateway)
            )

    def test_use_localhost(self):
        gateway = '::1'
        result = self.validator.validate(gateway)
        self.assertEquals(
            ValidationError(
                property_name='gateway',
        error_message='The gateway address ::1 cannot be local loopback.'
                ),
        result
            )

    def test_reserved(self):
        result = self.validator.validate('00b8::0')
        self.assertEqual(
            ValidationError(
                        property_name='gateway',
                        error_message='The gateway address 00b8::0 cannot be reserved.'),
            result
            )


class TestVMFirewallRulesItem(unittest.TestCase):

    def setUp(self):
        self.model_manager = ModelManager()
        self.validator = self.model_manager.validator
        self.ext = LibvirtExtension()

        self.prop_types = dict()
        for prop_type in self.ext.define_property_types():
            self.prop_types[prop_type.property_type_id] = prop_type

    def test_source_destination_validator_without_error(self):
        validator = SourceProviderValidator()
        result = validator.validate({"provider" : "iptables",
                                    "source" : "10.10.10.10"})
        self.assertEqual(None, result)

    def test_source_destination_validator(self):
        validation_cases = [
            {"props": {"provider": "iptables",
                       "source": "fefe:fefe:fefe:fefe"},
             "error": "Invalid combination of iptables and an IPv6 address "
                      "for the 'provider' and 'source' properties."},
            {"props": {"provider": "ip6tables",
                       "source": "10.10.10.10"},
             "error": "Invalid combination of ip6tables and an IPv4 address "
                      "for the 'provider' and 'source' properties."}
        ]
        for case in validation_cases:
            self._src_provider_validator_error(case["props"], case["error"])

    def _src_provider_validator_error(self, props, error):
        validator = SourceProviderValidator()
        expected = ValidationError(error_message=error)
        result = validator.validate(props)
        self.assertEqual(expected, result)

    def test_subnet_validator_fail(self):

        props_list = [
                        {"props" : {"provider" : "iptables",
                                    "source" : "1.2.1/44"},
                        "error" : "Invalid prefix for destination IPv4 network at '1.2.1/44'"},
                        {"props" : {"provider" : "iptables",
                                    "source" :"1000.2000.888.1/44"},
                        "error" : "Invalid IPv4 subnet value '1000.2000.888.1/44'"},
                        {"props" : {"provider" : "ip6tables",
                                    "source" : "A.b.c/1"},
                        "error" : "Invalid IPv6 subnet value 'A.b.c/1'"},
                        {"props" : {"provider" : "ip6tables",
                                    "source" :"FFFF.EEEE.DDDD.C/A"},
                        "error" : "Invalid IPv6 subnet value 'FFFF.EEEE.DDDD.C/A'"}
                    ]
        validator = SubnetValidator()

        for props in props_list:
            error = ValidationError(error_message=props.get('error'))
            self.assertEquals(error, validator.validate(props.get('props')))


    def test_subnet_validator_pass(self):

        validator = SubnetValidator()
        props_list = [
                        {"provider" : "iptables",
                        "source" :"10.247.244.0/22"},
                        {"provider" : "ip6tables",
                        "source" :"2001:1b70:82a1:103::1/64"}
                    ]

        for props in props_list:
            self.assertEquals(None, validator.validate(props))

    def test_dport_range_validator(self):

        validator = VmPortRangeValidator()
        dport_list = ["30-22", "65535-0", "22-22"]
        error_msg = "Invalid port range (min >= max)"
        expected_error = ValidationError(error_message=error_msg)
        for dport in dport_list:
            self.assertEquals(expected_error, validator.validate(dport))

if __name__ == '__main__':
    unittest.main()
