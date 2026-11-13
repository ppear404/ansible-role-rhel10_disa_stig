#!/usr/bin/python3
"""Read-only validation of a reviewed firewalld host baseline. JSON output only."""
import ipaddress
import json
import subprocess
from pathlib import Path


def command(*args):
    result = subprocess.run(args, capture_output=True, text=True, timeout=20, check=False,
                            env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'})
    if result.returncode:
        raise ValueError('Command failed: ' + ' '.join(args))
    return result.stdout.strip()


def fields(text):
    values = {}
    current = None
    for line in text.splitlines()[1:]:
        if not line.strip():
            continue
        if line.startswith('  ') and not line.startswith('    ') and ':' in line:
            current, value = line.strip().split(':', 1)
            if current in values:
                raise ValueError('Duplicate firewall field: ' + current)
            values[current] = value.strip()
        elif current == 'rich rules':
            values[current] += ('\n' if values[current] else '') + line.strip()
        else:
            raise ValueError('Unrecognized firewall output')
    return values


def firewall(permanent, *args):
    return command('firewall-cmd', *(['--permanent'] if permanent else []), *args)


def validate():
    policy_path = Path('/etc/security/rhel10-stig-firewall-approved.json')
    info = policy_path.stat()
    if info.st_uid != 0 or info.st_gid != 0 or info.st_mode & 0o777 != 0o600:
        raise ValueError('Unsafe firewall approval record')
    approved = json.loads(policy_path.read_text())
    if not approved.get('approval') or not approved.get('services') or not approved.get('interfaces'):
        raise ValueError('Missing explicit approved firewall baseline')
    if set(approved['services']) != {'ssh', 'cockpit', 'dhcpv6-client'}:
        raise ValueError('This validator requires review before changing approved service types')
    for operation, expected in [('is-active', 'active'), ('is-enabled', 'enabled')]:
        if command('systemctl', operation, 'firewalld.service') != expected:
            raise ValueError('firewalld must be active and enabled')
    if command('firewall-cmd', '--state') != 'running':
        raise ValueError('firewalld not running')
    command('firewall-cmd', '--check-config')
    zone_name = approved['zone']
    if command('firewall-cmd', '--get-default-zone') != zone_name:
        raise ValueError('Unapproved default zone')
    zone_fields = {'target', 'ingress-priority', 'egress-priority', 'icmp-block-inversion',
                   'interfaces', 'sources', 'services', 'ports', 'protocols', 'forward',
                   'masquerade', 'forward-ports', 'source-ports', 'icmp-blocks', 'rich rules'}
    policy_fields = {'disable', 'priority', 'target', 'ingress-zones', 'egress-zones',
                     'services', 'ports', 'protocols', 'masquerade', 'forward-ports',
                     'source-ports', 'icmp-blocks', 'rich rules'}
    zone_inventory = []
    policy_inventory = []
    for permanent in [False, True]:
        zones = firewall(permanent, '--get-zones').split()
        if zone_name not in zones:
            raise ValueError('Approved zone is missing')
        for zone in zones:
            data = fields(firewall(permanent, '--zone=' + zone, '--list-all'))
            if set(data) != zone_fields:
                raise ValueError('Unknown zone attributes require review')
            bound = bool(data['interfaces'] or data['sources'])
            if zone != zone_name:
                if bound:
                    raise ValueError('Unexpected bound zone: ' + zone)
                continue  # Dormant stock zones do not currently handle traffic.
            if data['sources']:
                raise ValueError('Unexpected source-zone binding')
            interfaces = set(data['interfaces'].split())
            if (not permanent and interfaces != set(approved['interfaces'])) or (
                    permanent and interfaces not in (set(), set(approved['interfaces']))):
                raise ValueError('Unexpected firewall interface bindings')
            expected = {'target': 'default', 'ingress-priority': '0', 'egress-priority': '0',
                        'icmp-block-inversion': 'no', 'ports': '', 'protocols': '',
                        'forward': 'yes', 'masquerade': 'no', 'forward-ports': '',
                        'source-ports': '', 'icmp-blocks': '', 'rich rules': ''}
            if any(data[key] != value for key, value in expected.items()):
                raise ValueError('Unexpected zone target, forwarding or rule configuration')
            if set(data['services'].split()) != set(approved['services']):
                raise ValueError('Allowed services differ from approved list')
            zone_inventory.append((permanent, zone, data))
        for service, definition in approved['services'].items():
            data = fields(firewall(permanent, '--info-service=' + service))
            expected = {'ports': definition['ports'], 'protocols': '', 'source-ports': '',
                        'modules': '', 'destination': definition['destination'],
                        'includes': '', 'helpers': ''}
            if data != expected:
                raise ValueError('Service definition changed: ' + service)
        for operation in ['--get-all-rules', '--get-all-chains', '--get-all-passthroughs']:
            if firewall(permanent, '--direct', operation):
                raise ValueError('Direct firewall configuration requires review')
        for policy in firewall(permanent, '--get-policies').split():
            text = firewall(permanent, '--info-policy=' + policy)
            data = fields(text)
            if set(data) != policy_fields:
                raise ValueError('Unknown policy attributes require review')
            if data['disable'] == 'yes':
                if not permanent and '(active)' in text.splitlines()[0]:
                    raise ValueError('Disabled policy unexpectedly active')
                continue
            if policy != 'allow-host-ipv6' or not approved.get('allow_standard_ipv6_control'):
                raise ValueError('Unapproved enabled firewall policy: ' + policy)
            control = ['mld-listener-done', 'mld-listener-query', 'mld-listener-report',
                       'mld2-listener-report', 'neighbour-advertisement', 'neighbour-solicitation',
                       'redirect', 'router-advertisement']
            expected = {'disable': 'no', 'priority': '-15000', 'target': 'CONTINUE',
                        'ingress-zones': 'ANY', 'egress-zones': 'HOST', 'services': '',
                        'ports': '', 'protocols': '', 'masquerade': 'no', 'forward-ports': '',
                        'source-ports': '', 'icmp-blocks': '',
                        'rich rules': '\n'.join('rule family="ipv6" icmp-type name="' + name + '" accept'
                                                for name in control)}
            if data != expected:
                raise ValueError('IPv6 control policy differs from reviewed stock policy')
            policy_inventory.append((permanent, policy, data))
    if {p for permanent, p, _ in policy_inventory if permanent} != {
            p for permanent, p, _ in policy_inventory if not permanent}:
        raise ValueError('Runtime and persistent enabled policies differ')
    # NetworkManager owns the persistent interface binding on this host.
    for interface in approved['interfaces']:
        uuid = command('nmcli', '-g', 'GENERAL.CON-UUID', 'device', 'show', interface)
        if not uuid or uuid == '--':
            raise ValueError('Cannot establish persistent interface connection')
        zone = command('nmcli', '-g', 'connection.zone', 'connection', 'show', uuid)
        if zone not in ('', zone_name):
            raise ValueError('NetworkManager persistent zone differs')
    tables = json.loads(command('nft', '-j', 'list', 'tables'))['nftables']
    actual = {(item['table']['family'], item['table']['name']) for item in tables if 'table' in item}
    if actual != {('inet', 'firewalld')}:
        raise ValueError('Unexpected or missing kernel firewall tables')
    listeners = []
    for line in command('ss', '-H', '-lntu').splitlines():
        parts = line.split()
        if len(parts) < 5 or parts[0] not in ('tcp', 'udp'):
            raise ValueError('Unrecognized listener output')
        protocol, address = parts[0], parts[4]
        host, port = address.rsplit(':', 1)
        host = host.split('%', 1)[0].strip('[]')
        if not port.isdigit():
            raise ValueError('Unrecognized listener port')
        loopback = host not in ('*', '0.0.0.0', '::') and ipaddress.ip_address(host).is_loopback
        if loopback:
            continue
        if f'{port}/{protocol}' not in {v['ports'] for v in approved['services'].values()}:
            raise ValueError('Unapproved non-loopback listener: ' + protocol + ' ' + address)
        listeners.append(protocol + ' ' + address)
    ipv6 = command('sysctl', '-n', 'net.ipv6.conf.all.disable_ipv6')
    return {'valid': True, 'results': 'Approved services ssh (22/tcp), cockpit (9090/tcp), dhcpv6-client '
            '(546/udp, IPv6 link-local). firewalld active/enabled; runtime/permanent public zone, '
            'service definitions, policy/direct rules and NetworkManager bindings verified. '
            'Only firewalld kernel table present. Non-loopback listeners: ' + ', '.join(listeners)
            + '. IPv6 all.disable_ipv6=' + ipv6
            + '. Dormant unbound zones/disabled policies do not establish active exposure. '
            'Approval source: ' + approved['approval']}


if __name__ == '__main__':
    try:
        print(json.dumps(validate()))
    except Exception as error:
        print(json.dumps({'valid': False, 'results': str(error)}))
