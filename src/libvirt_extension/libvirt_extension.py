##############################################################################
# COPYRIGHT Ericsson AB 2013
#
# The copyright to the computer program(s) herein is the property of
# Ericsson AB. The programs may be used and/or copied only with written
# permission from Ericsson AB. or in accordance with the terms and
# conditions stipulated in the agreement/contract under which the
# program(s) have been supplied.
##############################################################################

import binascii
import struct
from Crypto.Util.number import bytes_to_long, size
import netaddr
import re

from litp.core.extension import ModelExtension
from litp.core.litp_logging import LitpLogger
from litp.core.model_type import (Collection, ItemType, Property, PropertyType,
                                  View)
from litp.core.validators import (PropertyValidator,
                                  ValidationError,
                                  IPAddressValidator,
                                  ItemValidator,
                                  IsNotDigitValidator,
                                  NetworkValidator,
                                  NetworkValidatorV6,
                                  PropertyLengthValidator)
from litp.core.exceptions import ViewError

log = LitpLogger()

DYNAMIC_IP = "dhcp"
RSA_MINIMUM_LENGTH = 2048
INT_LENGTH = 4
DEFAULT_IPV6_MASK = "/64"

IPV6_NOT_IN_THE_SAME_SUBNET = ("The IPv6 addresses defined in the "
                               "ipv6addresses property must be within the same"
                               " subnet.")
GWV6_AND_IPV6_NOT_IN_THE_SAME_SUBNET = ("The IP address defined for the "
                                        "gateway6 property must be within the "
                                        "same subnet as the IP addresses "
                                        "defined for the ipv6addresses "
                                        "property")

IPV6_IS_MULTICAST = ("A multicast address '{0}' cannot be used as an IPv6"
                     " address.")
IPV6_IS_RESERVED = ("A reserved address '{0}' cannot be used as an IPv6 "
                    "address.")
IPV6_IS_LOCAL_LINK = ("A local link address '{0}' cannot be used as an IPv6 "
                      "address.")
IPV6_IS_LOOP_BACK = ("A loopback address '{0}' cannot be used a an IPv6 "
                     "address.")
IPV6_IS_NOT_VALID = "IPv6 address '{0}' is not valid"


class LibvirtExtension(ModelExtension):
    """
    Allows for the modelling of 'libvirt-provider' and 'libvirt-sytem' items.
    """
    # constant string is used in Libvirt_plugin
    REGEX_CHECKSUM_STRING = r"^(|[a-fA-f0-9]{32})$"
    HOSTNAME_REGEX = r"([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)"
    SCRIPT_NAME_REGEX = r"([A-Za-z0-9_][A-Za-z0-9_\.-]{0,30})"
    NFS_MOUNT_OPTIONS_REGEX = r'[a-z0-9_=\.:"]+'
    RAM_MOUNT_OPTIONS_REGEX = r"[\w=\.:%]+"

    def define_property_types(self):
        property_types = []
        error_desc = 'Value must be greater than or equal to 32 ' \
                     'followed by "M".'
        property_types.append(PropertyType("libvirt_ram_size",
                                           regex="^[0-9]+M$",
                                           validators=[MBRangeValidator(
                                               min_value="32M")],
                                           regex_error_desc=error_desc),)
        error_desc = "Value must follow one of the supported " \
                     "schemes (http, https)."
        property_types.append(PropertyType("libvirt_url",
                    regex=r"^((http|https)://[a-zA-Zf0-9\./\-_:]+)$",
                    regex_error_desc=error_desc))
        property_types.append(PropertyType("vm_repo_name",
                                           regex=r'^[a-zA-Z0-9\-\._]+$'))
        property_types.append(PropertyType("internal_status_check",
                                           regex=r'^on|off$'))
        property_types.append(PropertyType(
            "checksum_string", regex=LibvirtExtension.REGEX_CHECKSUM_STRING))
        property_types.append(PropertyType("nfs_mount_options",
                 regex=r"^({0}(,{0})*)$".format(self.NFS_MOUNT_OPTIONS_REGEX),
                    validators=[MountOptionsValidator()]))
        property_types.append(PropertyType("device_path",
                    validators=[DevicePathValidator()]))
        error_desc = 'Value must be "eth" followed by a number between' \
                     ' 0 and 14'
        property_types.append(PropertyType("libvirt_device_name",
                                           regex=r'^(eth([0-9]|1[0-4]))$',
                                           regex_error_desc=error_desc))
        property_types.append(PropertyType("libvirt_ssh_key",
                                           validators=[SSHKeyValidator()]))
        property_types.append(PropertyType("comma_separated_vm_hostnames",
            regex=r"^({0}(,{0})*)$".format(self.HOSTNAME_REGEX),
            validators=[IsNotDigitValidator(), DuplicateEntriesValidator()]))

        property_types.append(PropertyType('libvirt_ipv6_gateway_address',
            regex=r"^[0-9a-zA-Z:]*$",
            regex_error_desc='Value must be an IPv6 address',
            validators=[Gateway6Validator()]))
        property_types.append(PropertyType('ram_mount_type',
            regex=r"^tmpfs|ramfs$",
            regex_error_desc='Must be either tmpfs or ramfs.'))

        property_types.append(PropertyType('cpuset_range',
                                           validators=[CpuSetValidator()]))
        property_types.append(PropertyType(
                'positive_integer_list',
                validators=[PositiveIntegerListValidator()]))

        property_types.append(PropertyType("ram_mount_options",
                 regex=r"^({0}(,{0})*)$".format(self.RAM_MOUNT_OPTIONS_REGEX)))
        error_desc = ('Value can only contain numbers 0-9, upper or lower '
                     'case letters A-Z, hyphens, underscores and full stops '
                     'and can be no longer than 31 characters')
        property_types.append(PropertyType("comma_separated_scripts",
            regex=r"^({0}(,{0})*)$".format(self.SCRIPT_NAME_REGEX),
            regex_error_desc=error_desc,
            validators=[DuplicateEntriesValidator(),
                        MaxCustomScriptsValidator()]))
        error_desc = ('Value must be a number 0-999, followed by a '
                      'space, followed by a name containing only upper or '
                      'lower case letters A-Z, digits, whitespace, '
                      'underscores and hyphens. The value can be no longer '
                      'than 255 characters.')
        property_types.append(PropertyType("vm_firewall_rule_name",
            regex=r"^([0-9]){1,3}(\s([A-Za-z0-9_ -])+)?$",
            regex_error_desc=error_desc,
            validators=[PropertyLengthValidator(255)]))
        property_types.append(PropertyType("vm_firewall_rule_action",
                                           regex=r"^(accept|drop)$",
                                           regex_error_desc="Property must be"
                                           " either 'accept' or 'drop'"))
        error_desc = ('Value must be a valid IPv4/IPv6 network subnet.')
        property_types.append(PropertyType("vm_firewall_rule_ip_subnet",
                          regex=r"^[0-9a-fA-F.:]+/[0-9]{1,3}$",
                          regex_error_desc=error_desc))
        error_desc = ("Value must be either 'iptables' or 'ip6tables'.")
        property_types.append(PropertyType("vm_firewall_rule_provider",
                                           regex=r"^(iptables|ip6tables)$",
                                           regex_error_desc=error_desc))
        error_desc = ("Value must be one of either 'tcp' or 'udp'")
        property_types.append(PropertyType("vm_firewall_rule_protocol",
                                          regex=r"^(tcp|udp)$",
                                          regex_error_desc=error_desc))
        error_desc = ("Value of a port must be a number between 0 and 65535."
                      " A range using '-' is also supported.")
        valid_port = (r"(6553[0-5]|655[0-2][0-9]|65[0-4][0-9]{2}|"
                      r"6[0-4][0-9]{3}|[1-5][0-9]{4}|[1-9][0-9]{1,3}|[0-9])")
        property_types.append(PropertyType("vm_firewall_rule_port",
            regex=(r"^" + valid_port + r"(-" + valid_port + r")?$"),
            regex_error_desc=error_desc,
            validators=[VmPortRangeValidator()])
        )
        return property_types

    def define_item_types(self):
        item_types = []
        item_types.append(
            ItemType("libvirt-provider",
                     extend_item="system-provider",
                     item_description="A libvirt Virtual Machine provider.",
                     name=Property("basic_string",
                                   prop_description="Name of this "
                                                    "libvirt-provider.",
                                   updatable_rest=False,
                                   required=True
                                   ),
                     bridge=Property("basic_string",
                                     prop_description="Bridge interface name.",
                                     default="br0",
                                     updatable_rest=False
                                     ),
                     systems=Collection("libvirt-system")
                    )
            )
        item_types.append(
                ItemType("libvirt-system",
                         extend_item="system",
                         item_description="A librvirt Virtual Machine.",
                         path=Property("path_string",
                                       prop_description="Path for VM image "
                                       "(Please ensure this path has "
                                       "appropriate space for the "
                                       "specified VM's).",
                                       default="/var/lib/libvirt/images",
                                       updatable_rest=False
                                ),
                         ram=Property("libvirt_ram_size",
                                      prop_description="Size of RAM for "
                                      "Virtual Device in Megabytes.",
                                      default="2048M",
                                      updatable_rest=False
                                     ),
                         cpus=Property("positive_integer",
                                       prop_description="The number of CPUs "
                                       "to be given to a VM. It is "
                                       "recommended that either 1 or an even "
                                       "number is used.",
                                       default="2",
                                       updatable_rest=False
                                      ),
                        )
                )
        item_types.append(
            ItemType("vm-service",
                     extend_item="service",
                     item_description="This item type represents a VM (virtual"
                     " machine) service, which is a service that defines a VM "
                     "configuration.",
                     image_name=Property("basic_string",
                               prop_description="Name for VM image",
                               required=True
                     ),
                     image_checksum=Property('checksum_string',
                            prop_description="Checksum of the vm-image",
                            updatable_plugin=True,
                            updatable_rest=False,
                            required=False,
                            default=""),
                     motd_checksum=Property('checksum_string',
                            prop_description="Checksum of the motd message",
                            updatable_plugin=True,
                            updatable_rest=False,
                            required=False),
                     issue_net_checksum=Property('checksum_string',
                            prop_description="Checksum of the issue.net "
                                             "message",
                            updatable_plugin=True,
                            updatable_rest=False,
                            required=False),
                     ram=Property("libvirt_ram_size",
                              prop_description="Size of RAM for "
                              "VM in mebibytes",
                              default="256M",
                     ),
                     cpus=Property("positive_integer",
                               prop_description="Number of CPUs to be "
                               "given to VM.",
                               default="1"
                     ),
                     cpunodebind=Property("positive_integer_list",
                               prop_description="Lock a guest to a NUMA node "
                                                "or physical CPU set (mutually"
                                                " exclusive with cpuset)." +
                                                PositiveIntegerListValidator.
                                          DESC,
                               required=False),
                     cpuset=Property(
                             "cpuset_range", required=False,
                             prop_description="Lock a guest to a NUMA node or"
                                              " physical CPU set (mutually "
                                              "exclusive with cpunodebind). "
                                              "" + CpuSetValidator.DESC),
                     internal_status_check=Property("internal_status_check",
                                                    prop_description="Allows "
                                                    " to enable/disable the"
                                                    " internal status check"
                                                    " of the VM",
                                                    default="on"),
                     vm_yum_repos=Collection("vm-yum-repo"),
                     vm_zypper_repos=Collection("vm-zypper-repo"),
                     vm_packages=Collection("vm-package"),
                     vm_network_interfaces=Collection("vm-network-interface"),
                     vm_aliases=Collection("vm-alias"),
                     vm_nfs_mounts=Collection("vm-nfs-mount"),
                     vm_disks=Collection("vm-disk"),
                     vm_ssh_keys=Collection("vm-ssh-key"),
                     vm_ram_mounts=Collection("vm-ram-mount", max_count=1),
                     vm_custom_script=Collection("vm-custom-script",
                                                 max_count=1),
                     vm_firewall_rules=Collection("vm-firewall-rule"),
                     adaptor_version=Property("basic_string",
                                              prop_description="Version of the"
                                              " adaptor installed on the"
                                              " nodes. This property is for"
                                              " internal use only and cannot"
                                              " be set by the user",
                                              required=False,
                                              updatable_plugin=True,
                                              updatable_rest=False),
                     hostnames=Property("comma_separated_vm_hostnames",
                         prop_description="Hostnames that are allocated to the"
                         " virtual machines",
                         required=False
                        ),
                     node_hostname_map=Property('any_string',
                        prop_description=("A mapping of nodes to VM hostnames."
                                          " This is a read-only property used "
                                          "by the plugin to keep track of "
                                          "allocated hostnames"),
                        required=True, default="{}",
                        updatable_plugin=True, updatable_rest=False)
                     )
        )
        item_types.append(
            ItemType("vm-image",
                     extend_item="image-base",
                     item_description="This item type represents a VM (virtual"
                     " machine) image, where a VM image is a disk image of the"
                     " VM which defines the URI to the image file.",
                     name=Property('basic_string',
                            prop_description="Name of the image",
                            updatable_rest=False,
                            updatable_plugin=False,
                            required=True),
                     source_uri=Property('libvirt_url',
                            prop_description="URI to the image file",
                            required=True),
                     checksum=Property('checksum_string',
                                       prop_description=("Checksum of the "
                                                         "image"),
                                       updatable_plugin=True,
                                       updatable_rest=False,
                                       required=False,
                                       default=""),
            )
        )
        item_types.append(
            ItemType(
                "vm-yum-repo",
                item_description="This item type represents VM (virtual "
                "machine) Yum repository configuration.",
                name=Property(
                    "vm_repo_name",
                    prop_description="VM yum repository name",
                    updatable_plugin=False,
                    updatable_rest=False,
                    required=True),
                base_url=Property(
                    "yum_base_url",
                    prop_description="VM yum repository URL",
                    required=True),
                checksum=Property(
                    'checksum_string',
                    prop_description="checksum for vm-yum-repo",
                    updatable_plugin=True,
                    updatable_rest=False,
                    default="")
            )
        )
        item_types.append(
            ItemType(
                "vm-zypper-repo",
                item_description="This item type represents VM (virtual "
                "machine) Zypper repository configuration.",
                name=Property(
                    "vm_repo_name",
                    prop_description="VM zypper repository name",
                    updatable_plugin=False,
                    updatable_rest=False,
                    required=True),
                base_url=Property(
                    "yum_base_url",
                    prop_description="VM repository URL",
                    required=True),
                checksum=Property(
                    'checksum_string',
                    prop_description="checksum for vm-zypper-repo",
                    updatable_plugin=True,
                    updatable_rest=False,
                    default="")
            )
        )
        item_types.append(
            ItemType(
                "vm-package",
                item_description="This item type represents a VM (virtual "
                "machine) package to install.",
                name=Property(
                    "basic_string",
                    prop_description="VM package name",
                    required=True)
                )
        )
        item_types.append(
            ItemType("vm-network-interface",
                     item_description=("VM network interface."),
                     network_name=Property('basic_string',
                            prop_description=("Network to which interface "
                            "is attached"),
                            required=True),
                     device_name=Property('libvirt_device_name',
                            prop_description="Device name",
                            updatable_rest=True,
                            required=True),
                     host_device=Property("basic_string",
                            prop_description="Bridging device name.",
                            required=True),
                     ipaddresses=Property('basic_list',
                            prop_description=("IP addresses"),
                            required=False),
                     ipv6addresses=Property('any_string',
                            prop_description=("IPv6 addresses"),
                            required=False),
                     node_ip_map=Property('any_string',
                            prop_description=("Map VM IP addresses and nodes. "
                                              "This is a read-only property us"
                                              "ed by the plugin to keep track "
                                              "of allocated IPs"),
                            required=True, default="{}",
                            updatable_plugin=True, updatable_rest=False),
                     node_mac_address_map=Property('any_string',
                            prop_description=("A mapping of VM MAC addresses "
                                              "and nodes. This is a read-only "
                                              "property used to assign MAC "
                                              "addresses in a deterministic "
                                              "manner"),
                            required=True, default="{}",
                            updatable_plugin=True, updatable_rest=False),
                     mac_prefix=Property('any_string',
                            prop_description=("Vendor ID, First three octets"
                                              " of MAC addresses."),
                            required=False),
                     gateway=Property('ipv4_address',
                            prop_description=("IP address of the default "
                                              "gateway of the interface."),
                            required=False),
                     gateway6=Property('libvirt_ipv6_gateway_address',
                            prop_description=("IPv6 address of the default "
                                              "gateway of the interface."),
                            required=False),
                     validators=[MACAddressPrefixValidator(),
                                 IP46DHCPValidator(),
                                 StaticOrDynamicIPValidator(),
                                 IPv6AndMaskListValidator()]
            )
        )
        item_types.append(
            ItemType("vm-alias",
                     item_description=("Host entry in VM."),
                     alias_names=Property("comma_separated_alias_names",
                            prop_description="Hostname of the host entry",
                            site_specific=True,
                            required=True),
                     address=Property('ipv4_or_ipv6_address_with_prefixlen',
                            site_specific=True,
                            prop_description="IP address of the host entry",
                            required=True)
            )
        )
        item_types.append(
            ItemType("vm-nfs-mount",
                     item_description=("VM NFS mount."),
                     device_path=Property("device_path",
                                prop_description="Device path for the "
                                                 "NFS Mount.",
                                required=True,
                                site_specific=True),
                     mount_point=Property("path_string",
                                prop_description="The Mount path for "
                                                  "NFS mount",
                                required=True),
                     mount_options=Property("nfs_mount_options",
                                 prop_description="The mount options are \
                                 passed through to the VM image's /etc/ \
                                 fstab file.  The following mount options \
                                 are allowed:\
                                 \n \
                                 FILESYSTEM INDEPENDENT MOUNT OPTIONS: aysnc, \
                                 atime, noatime, auto, noauto, context, \
                                 defaults, dev, nodev, diratime, nodiratime, \
                                 dirsync, exec, noexec, group, iversion, \
                                 noiversion, mand, nomand, _netdev, nofail, \
                                 relatime, norelatime, strictatime, \
                                 nostrictatime, suid, nosuid, remount, ro, \
                                 _rnetdev, rw, sync, user, nouser, users.\
                                 \n \
                                 VERSION INDEPENDENT NFS MOUNT OPTIONS: soft, \
                                 hard, timeo, retrans, rsize, wsize, ac, \
                                 noac, acregmin, acregmax, acdirmax, \
                                 acdirmin, actimeo, bg, fg, retry, sec, \
                                 sharecache, nosharecache, resvport, \
                                 noresvport, lookupcache.\
                                 \n \
                                 VERSION 2 & 3 NFS MOUNT OPTIONS: proto, \
                                 udp, tcp, rdma, port, mountport, \
                                 mountproto, mounthost, mountvers, namlen, \
                                 nfsvers, vers, lock, nolock, intr, nointr, \
                                 cto, nocto, acl, noacl, rdirplus, \
                                 nordirplus, local_lock.\
                                 \n \
                                 VERSION 4 NFS MOUNT OPTIONS: clientaddr. \
                                 Support for each of these mount options is \
                                 dependent on what is supported on the \
                                 target virtual machine.",
                                 required=False,
                                 default="defaults")
            )
        )
        item_types.append(
            ItemType("vm-disk",
                     item_description="This item type represents a VM (virtual"
                     " machine) additional disk.",
                     host_volume_group=Property('basic_string',
                                       prop_description="The volume group"
                                                        " item ID.",
                                       required=True),
                     host_file_system=Property('basic_string',
                                       prop_description="The file system "
                                                        "item ID.",
                                       required=True),
                     mount_point=Property('path_string',
                                       prop_description="The mount point "
                                                    "inside the VM.",
                                       required=True),
                     host_file_system_item=View('file-system',
                         LibvirtExtension.get_filesystem_item,
                         view_description="The host file-system item. "
                            "This property is for internal use only and "
                            "cannot be set by the user."),
            )
        )
        item_types.append(
            ItemType("vm-ssh-key",
                     item_description=('This item type represents a public '
                                       'SSH key which is authorized in the '
                                       'VM. If no value is defined for the '
                                       'ssh_key property, the SSH key is '
                                       'ignored.'),
                     ssh_key=Property("libvirt_ssh_key",
                                prop_description="The public SSH key",
                                required=False,
                                site_specific=True)
            )
        )
        item_types.append(
            ItemType("vm-ram-mount",
                     item_description="VM RAM mount.",
                     type=Property("ram_mount_type",
                                prop_description="The file system type of VM "
                                                 "RAM mount. The type can be "
                                                 "either 'tmpfs' or 'ramfs'.",
                                required=True),
                     mount_point=Property("path_string",
                                prop_description="The mount path for VM RAM "
                                                  "mount.",
                                required=True),
                     mount_options=Property("ram_mount_options",
                                prop_description="Mount options for VM RAM "
                                                 "mount.",
                                required=True,
                                default="defaults")
            )
        )
        item_types.append(
            ItemType("vm-custom-script",
                item_description="This item type represents a customised "
                                 "script to install after booting.",
                network_name=Property('basic_string',
                    prop_description="Network name common to the Management "
                                     "Server and VM service where the custom "
                                     "scripts are going to be deployed. "
                                     "An empty value means the network to be "
                                     "used is the LITP Management Network.",
                    required=False,
                    updatable_rest=True,
                    updatable_plugin=False),
                custom_script_names=Property("comma_separated_scripts",
                    prop_description="VM custom script name",
                    required=True,
                    updatable_rest=True,
                    updatable_plugin=True)
             )
        )
        item_types.append(
          ItemType("vm-firewall-rule",
                   item_description="A firewall rule for a virtual machine.",
                   validators=[SourceProviderValidator(),
                              SubnetValidator()],
                   name=Property("vm_firewall_rule_name",
                            prop_description="The name which appears in the "
                            "iptables. The rules are sorted by the numerical "
                            "prefix of the name. This numerical prefix must "
                            "be unique per vm-service per provider type.",
                            required=True),
                   action=Property("vm_firewall_rule_action",
                            prop_description="Whether the packet is accepted "
                            "``(accept)`` or dropped ``(drop)``",
                            required=True),
                   source=Property("vm_firewall_rule_ip_subnet",
                            prop_description="The source address of the "
                            "packets. If set, this must be an IP address "
                            "subnet."),
                   provider=Property("vm_firewall_rule_provider",
                              prop_description="Specifies the iptables or "
                              "ip6tables to which the rule applies.",
                              required=True),
                   proto=Property("vm_firewall_rule_protocol",
                           prop_description="The protocol. The default value"
                           " is 'tcp'.",
                           default="tcp"),
                   dport=Property("vm_firewall_rule_port",
                           prop_description="The destination port. "
                           "This can be a single value or a range."
                           " The default value is '22'",
                           default="22"),
                   ),
        )

        return item_types

    @staticmethod
    def _find_file_system_in_volume_group(storage_profile, volume_group,
            file_system):
        """
        Returns ``file-system`` item for specified ``storage_profile``,
        ``volume_group``, ``file_system``.
        """
        for vg in storage_profile.query('volume-group', item_id=volume_group):
            for fs in vg.file_systems:
                if fs.item_id == file_system:
                    return fs

    @staticmethod
    def get_filesystem_item(plugin_api_context, vm_disk):
        """
        Returns ``file-system`` item for volume group and logical volume,
        specified for ``vm_disk``.

        Only logical volumes, defined on Management Server can be attached to
        virtual machine.
        """
        sp = plugin_api_context.query_by_vpath('/ms/storage_profile')
        if not sp:
            raise ViewError(
                "The storage profile for Management Server not found")

        fs = LibvirtExtension._find_file_system_in_volume_group(sp,
            vm_disk.host_volume_group, vm_disk.host_file_system)
        if not fs:
            raise ViewError("The file system {0} not found ".format(
                vm_disk.host_file_system))
        return fs


class PositiveIntegerListValidator(ItemValidator):
    """
    Validates that a list contains only positive integer values.
    """
    DESC = 'Valid values are a comma seperated list of ' \
           'positive integer values.'

    def validate(self, numeric_list):
        for token in numeric_list.split(','):
            try:
                if int(token) < 0:
                    raise ValueError
            except ValueError:
                msg = 'Invalid value \'' + token + '\'. ' + \
                      PositiveIntegerListValidator.DESC
                return ValidationError(error_message=msg)
        return None


class CpuSetValidator(ItemValidator):
    """
    Validates that the cpuset property contains valid numeric ranges that
     are acceptable by libvirt.
    """
    DESC = 'Valid values can be a range of numbers e.g 0-10; a ' \
           'comma sperated list of numbers e.g. 1,2,3 or a ' \
           'combination of range and list e.g 0-10,20,21,22 or ' \
           '1,2,3,9-15'

    def validate(self, cpuset):
        regex = '^([0-9]+)$|^([0-9]+)-([0-9]+)$'
        for token in cpuset.split(','):
            _match = re.search(regex, token)
            if not _match:
                # Nothing matched.
                msg = 'Invalid value \'' + cpuset + '\'. ' + \
                      CpuSetValidator.DESC
                return ValidationError(error_message=msg)
            # If group(1) is None then the second half of the regex matched.
            if not _match.group(1):
                # Matched a range [a-b] so check for something like 10-5 which
                # is invalid
                num_left = int(_match.group(2))
                num_right = int(_match.group(3))
                if num_left > num_right:
                    msg = 'Invalid value \'' + cpuset + '\'. ' + \
                          CpuSetValidator.DESC
                    return ValidationError(error_message=msg)
        return None


class StaticOrDynamicIPValidator(ItemValidator):
    """
    Validates that the value of the property do not mix dynamic and \
    static IP addresses and that dhcp value is defined once.
    """

    def validate(self, properties):
        ipaddresses = properties.get('ipaddresses')
        if ipaddresses:
            error_message = None
            ips = [ip.strip() for ip in ipaddresses.split(",")]
            dhcp_ips = [ip for ip in ips if ip == DYNAMIC_IP]
            if dhcp_ips and len(dhcp_ips) != len(ips):
                error_message = ("Invalid list: '%s'. The list can not "
                                 "contain a mix of static and dynamic IP "
                                 "addresses" % ipaddresses)
            elif len(dhcp_ips) > 1:
                error_message = ("Invalid list: '%s'. The list can not "
                                 "contain more than one dhcp "
                                 "value" % ipaddresses)
            if error_message:
                return ValidationError(error_message=error_message)


class IP46DHCPValidator(ItemValidator):
    """
    Custom ItemValidator for the ipaddresses and ipv6addresses list that checks
    the IPv4, IPv6 and dhcp value
    """

    def validate(self, properties):
        ipaddresses = properties.get('ipaddresses')
        if ipaddresses:
            ip_list = [ip.strip() for ip in ipaddresses.split(",")]
            validator = IPAddressValidator("both")
            for ip in ip_list:
                if ip != DYNAMIC_IP:
                    error = validator.validate(ip)
                    if error is not None:
                        return error


class IPv6AndMaskListValidator(ItemValidator):
    """
    Custom ItemValidator for the ipv6addresses list that checks
    1. if the IPv6 addresses are valid
    2. that they all belong to the same subnet
    3. that if the gateway6 property has been defined, its IP address is in the
    same subnet as the IP addresses in the ipv6addresses property.

    The IPv6 address may or may not contain a network prefix mask.
    """

    @staticmethod
    def normalize_ip(ip):
        """ If `ip` has no mask added the default 64. """
        if ip is not None and  "/" not in ip:
            ip = ip + DEFAULT_IPV6_MASK
        return ip

    @staticmethod
    def ipv6_validate(ipv6):
        """
        Return an error message if `ipv6`:
            1. hasn't a valid format
            2. is multicast address
            3. is loopback
            4. is reserved
            5. is local link
        """
        error_message = None
        try:
            net = netaddr.IPNetwork(ipv6, version=6)
        except netaddr.AddrFormatError:
            error_message = IPV6_IS_NOT_VALID.format(ipv6)
        else:
            if net.is_multicast():
                error_message = IPV6_IS_MULTICAST.format(ipv6)
            # IPNetwork('::1').is_loopback() does't work..
            elif netaddr.IPAddress(ipv6.split('/')[0]).is_loopback():
                error_message = IPV6_IS_LOOP_BACK.format(ipv6)
            elif net.is_reserved():
                error_message = IPV6_IS_RESERVED.format(ipv6)
            elif net.is_link_local():
                error_message = IPV6_IS_LOCAL_LINK.format(ipv6)

        return error_message

    def validate(self, properties):
        ipv6addresses = properties.get('ipv6addresses')

        if ipv6addresses:
            ip_list = [IPv6AndMaskListValidator.normalize_ip(ip.strip())
                       for ip in ipv6addresses.split(",")]
            for ipv6 in ip_list:
                # Validate the ip has the right format.
                error = IPv6AndMaskListValidator.ipv6_validate(ipv6)
                if error:
                    return ValidationError(error_message=error)

                # Validate all the ipv6 addresses are in the same subnet.
                netaddr_ip = netaddr.IPNetwork(ipv6)
                network, netmask = netaddr_ip.network, netaddr_ip.netmask
                try:
                    if (network, netmask) != (first_network, first_netmask):
                        return ValidationError(
                            error_message=IPV6_NOT_IN_THE_SAME_SUBNET)
                except NameError:
                    first_network, first_netmask = (netaddr_ip.network,
                                                    netaddr_ip.netmask)

            # Validate that gateway6 is in the same network like ipv6addresses.
            # In the libvirt plugin is the validation again if the gateway6
            # exist have to have also the ipv6.
            gateway6 = properties.get('gateway6')
            if gateway6:
                gateway6_addr_ip = netaddr.IPNetwork("{0}/{1}".format(
                    gateway6, str(first_netmask)))
                if gateway6_addr_ip.network != first_network:
                    return ValidationError(
                        error_message=GWV6_AND_IPV6_NOT_IN_THE_SAME_SUBNET)


class MACAddressPrefixValidator(ItemValidator):
    """
    Custom ItemValidator for MAC address prefix that checks
    if it consists of 3 octets and other validations.
    """

    def validate(self, properties):
        mac_prefix = properties.get('mac_prefix')
        if not mac_prefix:
            return

        if len(mac_prefix) != 8:
            return ValidationError(
                error_message="\"mac_prefix\" should be 8 symbols long. "
                    "For example: \"AA:BB:CC\".")

        try:
            fb, sb, tb = mac_prefix.split(':')
        except ValueError:
            return ValidationError(
                error_message="\"mac_prefix\" should consist of "
                                "three octets, separated by colon.")

        if len(fb) != 2 or len(sb) != 2 or len(tb) != 2:
            return ValidationError(
                error_message="\"mac_prefix\" should consist of "
                                "three octets, separated by colon.")
        try:
            int(fb, 16)
            int(sb, 16)
            int(tb, 16)
        except ValueError:
            return ValidationError(
                error_message="\"mac_prefix\" should consist of "
                                "three octets, separated by colon.")

        if fb[1].upper() not in ['2', '6', 'A', 'E']:
            return ValidationError(
                error_message='"mac_prefix" should contain a valid virtual '
                    'machine mac prefix. This means that the second digit of '
                    'the first octet must be one of four options: "2", "6", '
                    '"A" or "E". For example: "52:55:55"')


class MBRangeValidator(PropertyValidator):
    """Validates that the value of the property is within a range and
    it is in mebibytes, ending in 'M'.
    """

    def __init__(self, min_value=None, max_value=None):
        """
        MBRangeValidator.

        Validates the value of the property is within the given
        range of ``min_value`` and ``max_value``.

        :param min_value: Min value in mebibytes to validate against.
        :type  min_value: string
        :param max_value: Max value in mebibytes to validate against.
        :type  max_value: string

        :returns: Either a ValidationError object or None
        :type: litp.core.validators.ValidationError or None
        """
        super(MBRangeValidator, self).__init__()
        self.min_value = min_value
        self.max_value = max_value

    def validate(self, property_value):
        prop_val_int = -1
        try:
            if property_value[-1] != 'M':
                raise ValueError()
            prop_val_int = int(property_value[:-1])
        except ValueError:
            msg = ("Invalid value '{0}', numeric value in mebibytes expected."
                   " For example 'ram=256M'.".format(str(property_value)))
            err = ValidationError(error_message=msg)
            return err

        if self.min_value:
            min_value = self.min_value[:-1]
        if self.max_value:
            max_value = self.max_value[:-1]

        if (self.min_value and (prop_val_int < int(min_value))) or \
           (self.max_value and (prop_val_int > int(max_value))):
            if not self.min_value:
                msg = ('Invalid value "{0}". Value must be less than '
                       'or equal to {1}.'.format(property_value,
                                                 self.max_value))
                err = ValidationError(error_message=msg)
            elif not self.max_value:
                msg = ('Invalid value "{0}". Value must be greater than '
                       'or equal to {1}.'.format(property_value,
                                                self.min_value))
                err = ValidationError(error_message=msg)
            else:
                msg = ('Invalid value "{0}". Value must be in the range '
                       '[{1}, {2}].'.format(property_value, self.min_value,
                                                            self.max_value))
                err = ValidationError(error_message=msg)
            return err


class MountOptionsValidator(PropertyValidator):

    """
    Further validation is carried out by the MountOptionsValidator on the \
    mount_options property:

    The following are valid options only if "=n" is specified where n is a \
    numeric value: timeo=n, actimeo=n, retrans=n, rsize=n, wsize=n, \
    acregmin=n, acregmax=n, acdirmin=n, retry=n, minorversion=n, port=n

    For the following options please see validation notes below: proto=netid, \
    lookupcache=mode, clientaddr=IP, sec=mode

    "clientaddr": must be a valid IP Address (IPv4 or IPv6)

    "lookupcache": the value must be one \
of the following: none|all|pos|positive

    "sec": the value must be one of the following: none|sys|krb5|\
krb5i|krb5p|lkey|lkeyp|spkm|spkmi|spkmp

    "timeo": can only be used when the option "soft" is specified

    "proto": the value must be one of the following: tcp|tcp6|rdma

    The following options conflict and will throw an error if input together: \
    ("soft", "hard") ("ac", "noac")
    ("bg", "fg") ("sharecache", "nosharecache") \
    ("resvport", "noresvport") ("intr", "nointr")
    ("lock", "nolock") ("cto", "nocto") ('async', 'sync') \
    ('atime', 'noatime') ('auto', 'noauto')
    ('dev', 'nodev') ('diratime', 'nodiratime') \
    ('exec', 'noexec') ('iversion', 'noiversion')
    ('mand', 'nomand') ('relatime', 'norelatime') \
    ('strictatime', 'nostrictatime') ('suid', 'nosuid')
    ('ro', 'rw') ('user', 'nouser', 'users') ('acl', 'noacl') \
    ('rdirplus', 'nordirplus').
    """

    def validate(self, property_value):

        error_msgs = []

        mount_options = []

        if property_value:
            if ((not property_value[0].isalpha()  and
                property_value[0] != "_")
            or (not property_value[-1].isdigit()
            and not property_value[-1].isalpha())):
                msg = "Invalid format to string. " \
                      "Remove any whitespace or punctuation " \
                      "from start or end of string. "
                error_msgs.append(msg)

            options = [x.strip(',').strip() for x \
                       in property_value.split(',')
                       if x and not x.isspace()]

            for word in options:
                value = word.split('=')
                if value and value[0] not in mount_options:
                    mount_options.append(value[0])
                else:
                    msg = value[0] + ' has been entered more ' \
                                     'than once'
                    error_msgs.append(msg)
                if len(value) > 1:

                    validation_methods = [self._mount_option_is_valid(value),
                    self._compare_acregmin_acregmax(value, property_value),
                    self._compare_acdirmin_acdirmax(value, property_value),
                    self._option_has_value(value),
                    self._sec_option_value_is_valid(value),
                    self._proto_option_value_is_valid(value),
                    self._lookupcache_has_valid_parameter(value),
                    self._clientaddr_has_valid_ip(value),
                    self._timeo_option_is_valid(value, property_value)]

                    for message in validation_methods:
                        if message is not None:
                            error_msgs.append(message)

                else:
                    message = self._check_single_option(value)

                    if message is not None:
                        error_msgs.append(message)

            error_msg = self._contrast_mount_options(property_value)
            if error_msg:
                error_msgs.append(error_msg)

            if error_msgs:
                msg = ' '.join(error_msgs)
                return ValidationError(
                            property_name="mount_options",
                            error_message=msg)

    @staticmethod
    def _compare_acregmin_acregmax(value, property_value):
        if value[0] == "acregmin":
            options = [x.strip(',').strip() for x \
                   in property_value.split(',')
                   if x and not x.isspace()]
            for word in options:
                if "acregmax" in word:
                    acregmax_option = word.split('=')
                    if value[1].isdigit() and \
                            acregmax_option[1].isdigit():
                        if int(value[1]) > int(acregmax_option[1]):
                            return 'The value entered for nfs mount '\
                            'option "acregmin" exceeds the value '\
                            'entered for nfs mount "acregmax". Please refer '\
                            'to the man page for nfs mount.'

    @staticmethod
    def _compare_acdirmin_acdirmax(value, property_value):
        if value[0] == "acdirmin":
            options = [x.strip(',').strip() for x \
                   in property_value.split(',')
                   if x and not x.isspace()]
            for word in options:
                if "acdirmax" in word:
                    acdirmax_option = word.split('=')
                    if value[1].isdigit() and \
                            acdirmax_option[1].isdigit():
                        if int(value[1]) > int(acdirmax_option[1]):
                            return 'The value entered for nfs mount '\
                            'option "acdirmin" exceeds the value '\
                            'entered for nfs mount option "acdirmax". Please '\
                            'refer to the man page for nfs mount.'

    @staticmethod
    def _clientaddr_has_valid_ip(value):

        regex = re.compile('(clientaddr)')
        find = re.match(regex, value[0])
        if find is not None:
            validator = IPAddressValidator("both")
            if validator.validate(value[1]) is not None:
                msg = '"clientaddr" option "%s" has invalid ' \
                      'ipv4 or ipv6 address. Please refer to the man page '\
                      'for nfs mount.' % value[0]
                return msg

    @staticmethod
    def _check_single_option(value):

        regex = re.compile(r'\b(soft|hard)\b|'
                                 r'\b(ac|noac)\b|'
                                 r'\b(bg|fg)\b|'
                                 r'\b(defaults)\b|'
                                 r'\b(lock)\b|'
                                 r'\b(nolock)\b|'
                                 r'\b(noexec)\b|'
                                 r'\b(nosuid)\b|'
                                 r'\b(sharecache|nosharecache)\b|'
                                 r'\b(resvport|noresvport)\b|'
                                 r'\b(intr|nointr)\b|'
                                 r'\b(cto|nocto)\b|'
                                 r'\b(async|sync)\b|'
                                 r'\b(atime|noatime)\b|'
                                 r'\b(auto|noauto)\b|'
                                 r'\b(dev|nodev)\b|'
                                 r'\b(diratime|nodiratime)\b|'
                                 r'\b(dirsync)\b|'
                                 r'\b(exec|noexec)\b|'
                                 r'\b(group)\b|'
                                 r'\b(iversion|noiversion)\b|'
                                 r'\b(mand|nomand)\b|'
                                 r'\b(nofail)\b|'
                                 r'\b(relatime|norelatime)\b|'
                                 r'\b(strictatime|nostrictatime)\b|'
                                 r'\b(suid|nosuid)\b|'
                                 r'\b(remount)\b|'
                                 r'\b(ro|rw)\b|'
                                 r'\b(user|nouser|users)\b|'
                                 r'\b(acl|noacl)b|'
                                 r'\b(rdirplus|nordirplus)\b')

        find = re.match(regex, value[0])
        if find is None:
            msg = '"%s" is invalid mount option/nfs mount option. '\
                  'Please check the relevant man page.' % value[0]
            return msg

    @staticmethod
    def _lookupcache_has_valid_parameter(value):

        regex = re.compile('(lookupcache)')
        find = re.match(regex, value[0])

        if find is not None:
            regex = re.compile('(none|all|pos|positive)')
            if re.match(regex, value[1]) is None:
                msg = '"%s" is an invalid value for "lookupcache" nfs mount '\
                      'option. Valid values are (none|all|pos|positive). '\
                      'Please refer to the man page for '\
                      'nfs mount.' % value[1]
                return msg

    @staticmethod
    def _sec_option_value_is_valid(value):

        regex = re.compile('(sec)')
        find = re.match(regex, value[0])

        if find is not None:
            regex = re.compile(r'\b(none|sys|krb5|krb5i|krb5p '
                        r'|lkey|lkeyp|spkm|spkmi|spkmp)\b')
            if re.match(regex, value[1]) is None:
                msg = '"%s" is an invalid value for "sec" nfs mount option. '\
                      'Valid values are (none|sys|krb5|krb5i|krb5p' \
                      '|lkey|lkeyp|spkm|spkmi|spkmp). Please refer to the '\
                      'man page for nfs mount. ' % value[1]
                return msg

    @staticmethod
    def _proto_option_value_is_valid(value):

        regex = re.compile('(proto|mountproto)')
        find = re.match(regex, value[0])

        if find is not None:
            regex = re.compile(r'\b(udp|udp6|tcp|tcp6|rdma)\b')
            if re.match(regex, value[1]) is None:
                msg = '"%s" is an invalid value for proto nfs mount option. ' \
                      'Valid values are (udp|udp6|tcp|tcp6|rdma). Please '\
                      'refer to the man page for nfs mount.' % value[1]
                return msg

    @staticmethod
    def _option_has_value(value):

        regexp = re.compile(r'\b(timeo|retrans|rsize|wsize|'
                               r'acregmin|acregmax'
                               r'|acdirmin|acdirmax|actimeo|'
                               r'retry|minorversion|port|'
                               r'mountport|namlen)\b')

        find = re.match(regexp, value[0])

        if find is not None:
            if not value[1].isdigit():
                msg = '"%s" nfs mount_option requires a numeric value. '\
                      'Please refer to the man page for nfs mount.' % value[0]
                return msg

    @staticmethod
    def _mount_option_is_valid(value):

        regexp = re.compile(r'\b(sec|lookupcache|clientaddr|timeo|'
                                    r'retrans|rsize|'
                                    r'wsize|ac|noac|acregmin|acregmax'
                                    r'|acdirmin|acdirmax|actimeo|'
                                    r'retry|minorversion|'
                                    r'port|proto|'
                                    r'mountport|mountproto|mounthost|'
                                    r'mountvers|namlen|local_lock|'
                                    r'nfsvers|vers|'
                                    r'context|fscontext|defcontext|'
                                    r'rootcontext|'
                                    r'_netdev|_rnetdev)\b')

        find = re.match(regexp, value[0])
        if find is None:
            msg = '"%s" is not valid nfs mount options. ' \
            'Valid nfs mount options are ' \
            '(sec|lookupcache|clientaddr|timeo|actimeo|' \
            'retrans|rsize|wsize|ac|noac|acregmin|acregmax' \
            '|acdirmin|acdirmax|retry|minorversion|' \
            'port|proto|mountport|mountvers|mountproto|mounthost|namlen|' \
            'nfsvers|vers|context|fscontext|defcontext|_netdev|_rnetdev|'\
            'rootcontext|local_lock). Please refer to the man page for '\
            ' nfs mount.' % value[0]
            return msg

    @staticmethod
    def _timeo_option_is_valid(value, property_value):
        if "timeo" in value and not "actimeo" in value:
            if "soft" not in property_value:
                msg = 'Nfs mount option "timeo" requires the nfs mount '\
                      'option "soft". Please refer to the man page for nfs '\
                      'mount.'
                return msg

    @staticmethod
    def _contrast_mount_options(property_value):

        options = property_value.split(',')

        the_lists = [("soft", "hard"), ("ac", "noac"),
            ("bg", "fg"), ("sharecache", "nosharecache"),
            ("resvport", "noresvport"), ("intr", "nointr"),
            ("lock", "nolock"), ("cto", "nocto"), ("async", "sync"),
            ("atime", "noatime"), ("auto", "noauto"),
            ("dev", "nodev"), ("diratime", "nodiratime"), ("exec", "noexec"),
            ("iversion", "noiversion"), ("mand", "nomand"),
            ("relatime", "norelatime"), ("strictatime", "nostrictatime"),
            ("suid", "nosuid"), ("ro", "rw"), ("user", "nouser", "users"),
            ("acl", "noacl"), ("rdirplus", "nordirplus")]

        conflicted_opts = []
        for list_item in the_lists:
            if all(item in options for item in list_item):
                conflicted_opts.append('("%s")' % '", "'.join(list_item))

        msg_header = ("Conflicting nfs mount options. "
                      "Only one option should be chosen "
                      "from each of the following pairs")
        if not conflicted_opts:
            error_msg = ''
        elif len(conflicted_opts) > 1:
            error_msg = '%s: %s and %s.' % (msg_header,
                                           ', '.join(conflicted_opts[:-1]),
                                           conflicted_opts[-1])
        else:
            error_msg = '%s: %s.' % (msg_header, conflicted_opts[0])
        return error_msg


class DevicePathValidator(PropertyValidator):
    #pylint: disable=anomalous-backslash-in-string
    """
    Validates that the device_path for vm-nfs-mount is of correct format.
    The correct format is one of the following:
              hostname:/mnt/data
                  or
              ipaddress:/mnt/data
                  or
              hostname.org:/mnt/data

       IPv6 is not supported

       The regex for the above validation is of the following:

       host_regex = r"^(\.[a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]" \
        "{0,61}[a-zA-Z0-9])$"

        fqdn_hostname_regex = r"^(?=^.{4,253}$)(^((?!-)[a-zA-Z0-9-]" \
        r"{1,63}(?<!-)\.)+[a-zA-Z]{2,63}$)"

        path_string_regex = r"^/[A-Za-z0-9\-\._/#:\s*]+$"
    """

    def validate(self, property_value):

        if (not all(property_value.rpartition(':/')) or
            (' ' in property_value)):
            msg = 'Property device_path must take the form '\
                   '<hostname|IP>:<path>'
            err = ValidationError(error_message=msg)
            return err

        host_regex = r"^(\.[a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]" \
        "{0,61}[a-zA-Z0-9])$"
        fqdn_hostname_regex = r"^(?=^.{4,253}$)(^((?!-)[a-zA-Z0-9-]" \
        r"{1,63}(?<!-)\.)+[a-zA-Z]{2,63}$)"
        path_string_regex = r"^/[A-Za-z0-9\-\._/#:\s*]+$"

        host = re.compile(host_regex)
        path = re.compile(path_string_regex)
        fqdn_host = re.compile(fqdn_hostname_regex)

        device_path = property_value.split(":/", 1)
        #"/" added back on because split removes it
        device_path[1] = "/" + device_path[1]

        if not (netaddr.valid_ipv4(device_path[0]) \
                or host.match(device_path[0]) \
                or fqdn_host.match(device_path[0])) \
                or not path.match(device_path[1]):
            msg = 'Value of the property device_path "%s" is invalid.' \
                    % property_value
            err = ValidationError(error_message=msg)
            return err
        return None


class SSHKeyValidator(PropertyValidator):
    """Validates that the size is greater than or equals to 2048 and \
       the type is rsa
    """

    def validate(self, property_value):

        if not property_value:
            return

        err = None
        try:
            key_type, keystring = property_value.split(' ')[:2]
            data = binascii.a2b_base64(keystring)
            keyparts = []
            while len(data) > INT_LENGTH:
                l = struct.unpack(">I", data[:INT_LENGTH])[0]
                keyparts.append(data[INT_LENGTH:INT_LENGTH + l])
                data = data[INT_LENGTH + l:]
            # keyparts = [type, exponent, module]
            n = bytes_to_long(keyparts[2])
            key_len = size(n)
            if key_len < RSA_MINIMUM_LENGTH or key_type != keyparts[0]:
                msg = 'Invalid value: %s. The length of the key must be ' \
                      '2048 or higher.' % property_value
                err = ValidationError(error_message=msg)
        except (ValueError, IndexError, TypeError):
            msg = 'Invalid value: %s. The key must be a valid rsa key.' % \
                  property_value
            err = ValidationError(error_message=msg)

        return err


class DuplicateEntriesValidator(PropertyValidator):
    """
    Custom Validator for the optional 'hostnames' property
        (a comma-separated-list) on vm-service.

    Validates for multiple usages in the hostnames
    """

    def validate(self, property_value):
        err = None
        if not property_value:
            return err

        lst = property_value.split(",")

        multiple_usages = set(entry for entry in lst
            if lst.count(entry) > 1)
        if multiple_usages:
            msg = ('Invalid value: {0}. In this property the following '
                   'values have been specified more than once: {1}'.format(
                property_value, ', '.join(use for use in multiple_usages)))
            err = ValidationError(error_message=msg)
        return err


class Gateway6Validator(PropertyValidator):
    """
    Validates extra constraints an IPv6 address has when it is a
    gateway property within a vm-network-interface item.
    """
    def validate(self, property_value):

        if not property_value and property_value == u"":
            return None

        error = IPAddressValidator('6').validate(property_value)
        if error:
            return error

        gateway_string = property_value

        gateway_address = netaddr.IPAddress(gateway_string)

        # Can't have a multicast address as gateway!
        if gateway_address.is_multicast():
            return ValidationError(
                    property_name='gateway',
                    error_message='Cannot use multicast address {0} as'
                        ' gateway'.format(gateway_string))

        # Gateway cannot be local loopback
        if gateway_address.is_loopback():
            return ValidationError(
                property_name='gateway',
                error_message='The gateway address {0} '
                    'cannot be local loopback.'.format(gateway_string)
                )

        # Gateway cannot be 'undefined' address
        if gateway_address == netaddr.IPAddress('::'):
            return ValidationError(
                property_name='gateway',
                error_message='The gateway address {0} '
                    'cannot be the undefined address.'.format(gateway_string)
                )

        # Gateway cannot be link local
        if gateway_address.is_link_local():
            return ValidationError(
                property_name='gateway',
                error_message='The gateway address {0} '
                    'cannot be link-local.'.format(gateway_string)
                    )

        if gateway_address.is_reserved():
            return ValidationError(
                property_name='gateway',
                error_message='The gateway address {0} '
                    'cannot be reserved.'.format(gateway_string)
                )


class MaxCustomScriptsValidator(PropertyValidator):
    """
    Valiates the maximum number of scripts specified per vm-custom-script item
    is no greater than 5.
    """
    def validate(self, property_value):
        err = None
        if not property_value:
            return err

        lst = property_value.split(",")

        if len(lst) > 5:
            error_message = 'Max number of scripts allowed is 5'
            err = ValidationError(
                error_message=error_message
            )
        return err


class SourceProviderValidator(ItemValidator):
    """
    Validates that the provider and source properties \
    do not contain an invalid combination of IPv4 and IPv6 addresses.
    """

    def validate(self, properties):
        iptables = 'iptables'
        ip6tables = 'ip6tables'
        ipv4_address = 'an IPv4 address'
        ipv6_address = 'an IPv6 address'
        msg_template = ("Invalid combination of %s and %s for "
                        "the '%s' and '%s' properties.")
        error = None
        provider_prop = properties.get('provider', '')
        source_prop = properties.get('source', '')
        if provider_prop == 'iptables' and ':' in source_prop:
            msg = msg_template % (iptables, ipv6_address,
                                  'provider', 'source')
            error = ValidationError(error_message=msg)
        elif ip6tables in provider_prop and '.' in source_prop:
            msg = msg_template % (ip6tables, ipv4_address,
                                  'provider', 'source')
            error = ValidationError(error_message=msg)
        return error


class SubnetValidator(ItemValidator):
    """
    Validates that the ipaddress subnet is a valid IPv4 or IPv6 network.
    """
    def validate(self, properties):

        error = None
        provider_prop = properties.get('provider', '')
        source_prop = properties.get('source', '')

        if source_prop and provider_prop:
            validator = NetworkValidator() if provider_prop == 'iptables' \
                        else NetworkValidatorV6()

            error = validator.validate(source_prop)

        return error


class VmPortRangeValidator(PropertyValidator):
    def validate(self, property_value):
        err = None
        if not property_value:
            return err

        if "-" in property_value:
            min_port, max_port = [int(elem) for elem \
                                        in property_value.split("-")]
            if min_port >= max_port:
                error_message = "Invalid port range (min >= max)"
                err = ValidationError(
                    error_message=error_message
                )

        return err
