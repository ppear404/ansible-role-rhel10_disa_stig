# RHEL 10 STIG role

Remediation and validation support for the DISA RHEL 10 STIG **V1R3**.
This role applies additional configuration to the project's prepared RHEL 10
baseline. It does not implement every STIG control or establish compliance by
itself; evaluate the resulting system and retain the required site approvals.

## Required ISO baseline

**The base `.iso` was created in Red Hat's Image Builder.** It included most
STIG-required packages and partitions before this Ansible role was applied.
**The OpenSCAP STIG profile was applied at the ISO level, and FIPS was enabled
during the ISO build.** These are prerequisites of the tested baseline.

**The same results will not be achieved with a different base ISO.** The role
builds on the installation-time hardening, package selection, partition layout,
and FIPS configuration of that image. It does not recreate the Image Builder
ISO, repartition a generic installation, or enable FIPS on an arbitrary host.
Retain the image's build configuration when reproducing this environment.

## Current implementation

`tasks/main.yml` includes `tasks/cat2.yml`, which runs the implemented Category 2
controls and shared mount-option and audit-rule tasks. `cat1.yml` and `cat3.yml`
are not included in the normal role flow. Per-control implementations are in
`tasks/V-######.yml`, with shared helpers for audit commands, PAM password quality,
and firewall review.

The active flow covers filesystem protections, GRUB authentication, audit rules
and boot arguments, logging, USBGuard, Postfix and root mail aliases, PAM password
quality, DoD authentication roots, Chrony, daily AIDE scans, approved local
accounts, and firewall review records. Review `tasks/cat2.yml` for the current
includes and tag reachability.

## Requirements and configuration

- RHEL 10 installed from the prepared ISO described above, with package repositories
  available and privilege escalation to root.
- Install the controller collection dependency from the repository root:
  `ansible-galaxy collection install -r roles/rhel10-stig/requirements.yml`.
  The role declares `ansible.posix` and has no role dependencies.
- An existing, approved, nonempty `/var/lib/aide/aide.db.gz` for V-280980.
  The role deliberately requires this baseline rather than initializing it.
- Site-specific settings in host_vars/group_vars or play variables, as below.

| Variable | Default and purpose |
| --- | --- |
| `mount_options` | Mount paths and flags listed in `defaults/main.yml`; updates matching `defaults` entries in `/etc/fstab`. Requires the existing filesystem layout. |
| `grub_superuser` | `grubdev`, a GRUB-only account. |
| `grub_password_hash` | Development PBKDF2 hash; replace for other environments. |
| `rhel10_stig_root_mail_recipients` | `[system.administrator@mail.mil]`; set actual ISSO/SA destinations. |
| `rhel10_stig_time_servers` | `[]`; requires a nonempty list of approved authoritative DoW sources. |
| `rhel10_stig_authorized_local_accounts` | `[]`; requires an SA/ISSO-approved list covering all local potentially interactive accounts, including root. Unapproved accounts cause failure; they are not deleted automatically. |
| `rhel10_stig_firewall_approval` | `{}`; requires an approval reference, nonempty `services` mapping, and `interfaces` list. See `../../host_vars/rhel10-1.yml` for the current dev structure. |

The firewall tasks install/enable firewalld, record the approved baseline, and
install `/usr/local/sbin/rhel10-stig-firewall-validate`. They do not reconcile zone
rules automatically; run the validator and resolve differences against the
approved policy. Retain PPSM assessment references in the security plan.

## Running and validating

From the repository root, the existing `rhel10-v1r3-stig.yml` playbook targets dev
alias `rhel10-1` from `inventory.yml`, gathers facts, and uses `become: true`:

```sh
ansible-playbook -i inventory.yml rhel10-v1r3-stig.yml --syntax-check
ansible-playbook -i inventory.yml rhel10-v1r3-stig.yml --limit rhel10-1 --list-hosts
ansible-playbook -i inventory.yml rhel10-v1r3-stig.yml --limit rhel10-1 --check --diff
ansible-playbook -i inventory.yml rhel10-v1r3-stig.yml --limit rhel10-1
```

For a scoped control, add its supported tag, for example `--tags V-281336`.
Review the include and dependencies first: shared mount and audit installation
includes are untagged and are not automatically selected by every control tag.
Check mode is a preview; some read-only inspections still execute and checks
that depend on newly installed artifacts may require a real deployment.

Handlers can remount filesystems, rebuild GRUB, reload audit rules, and restart
services. **The audit handler reboots the host when changed rules must take
effect under immutable auditing.** Plan for that interruption. After deployment,
repeat the scoped play to check idempotence and validate runtime and persistent
state, including any boot-time settings that require a reboot.

Capture before-and-after results with the matching Evaluate-STIG check. Local
references are `../../files/disa-docs/U_RHEL_10_V1R3_STIG.zip` and
`../../files/eval-stig/evaluate-stig-1.2610.1/`. Control-specific evidence and test
commands are in `tests/`. The current AnswerFile is
`files/RHEL10_Answerfile.xml`; stage it in an evaluator AnswerFiles directory and
supply that directory with `-AFPath` and key `DEFAULT`. The role does not deploy
it automatically. Review its validation code and procedure comments before use;
manual procedures and approvals must be adopted in the site's security plan.
An Ansible success or AnswerFile status alone does not establish full compliance.

## Control notes

GRUB account (V-281167)
----------------------

`grub_superuser` defaults to `grubdev`; this is a GRUB account, not a Linux user.
`grub_password_hash` defaults to the GRUB PBKDF2 hash for the development password
`Grubdev-ChangeMe!2026`. Override it with a hash generated by `grub2-mkpasswd-pbkdf2`
for other environments. The role manages `/etc/grub.d/01_users` and
`/boot/grub2/user.cfg`, and regenerates `/boot/grub2/grub.cfg` when either changes.

Root mail recipients (V-280998)
------------------------------

Set `rhel10_stig_root_mail_recipients` in host_vars/group_vars or play variables.
Each entry can be a local username, email address, or distribution-list address.
The role joins the entries into the `root:` alias and rebuilds the Postfix alias
database when needed. The default preserves the current dev destination:

```yaml
rhel10_stig_root_mail_recipients:
  - system.administrator@mail.mil
```

For multiple recipients, add one list entry per destination. Choose recipients
that cover both ISSO and SA. Setting `[]` preserves the existing source alias;
if no alias exists, the role requires an explicit destination.

### PAM password quality (V-281214 / V-281215)

These control tags inspect authselect integrity and manage the active custom
profile's password-auth/system-auth templates. Existing enforcing `requisite`
or `required` rules are retained. Missing rules are inserted before password
writers and regenerated with an authselect backup. Unexpected profiles,
symlinked templates, duplicate/conditional rules, or non-enforcing layouts fail
for review. Generated /etc/pam.d files are never edited directly.

Evaluate-STIG 1.2610.1 incorrectly flags `requisite`. The role's
`files/RHEL10_Answerfile.xml` includes fail-closed live validation for this
mismatch. Supply its containing directory via `-AFPath` and use AnswerKey
`DEFAULT`; see `tests/V-281214-V-281215.md` for tested usage and evidence.

### DoD PKI authentication roots (V-281329)

Tag `V-281329` installs the reviewed DoD Root CA 3/4/5/6 PEM into
`/etc/sssd/pki/sssd_auth_ca_db.pem` as root:sssd 0640. The role pins the asset's
SHA-256 digest and refuses an unfamiliar existing database or a different
`pam_cert_db_path`. Review and revalidate certificates before changing the
asset/digest, including when preserving additional site trust is required.
Only an already running SSSD is restarted after a database change. Authselect
and the system-wide TLS trust store are not modified.

The source is `files/unclass-certificates_pkcs7_DoD.zip` (DoD PKI v5.14).
`python3 roles/rhel10-stig/tests/verify_v281329_package.py` verifies its package
signature, chain, manifest hashes, and deployed root asset; this controller-side
test requires Python cryptography and OpenSSL. See `tests/V-281329.md` for dev
results and the limits of configuration validation versus smart-card login.

### Category 2 task scaffolding

`tasks/cat2.yml` contains includes only. Control implementations live in
`tasks/V-######.yml`; audit-command and PAM controls use per-control entry files
that include their shared implementation helpers. Cross-control filesystem setup
and audit-bundle installation live in `mount_options.yml` and `audit_rules.yml`.
The extraction preserves the previous task order, variables, notifications and
tag reachability, including tasks that were previously untagged. The /dev/shm
mount task is grouped in V-281235.yml and retains all three existing mount flags
(nodev, noexec, nosuid; V-281235/V-281236/V-281237).

### V-281336 time servers

Set `rhel10_stig_time_servers` in host_vars/group_vars to a nonempty list of
site-approved authoritative DoW time server hostnames or IP addresses. The
default empty list stops before changing Chrony. The role sets each source to
`server <address> iburst maxpoll 16`, replaces existing server/pool/peer and
sourcedir directives (including DHCP sources), and restarts Chrony on changes.
Other Chrony settings are preserved. Review any additional include/confdir
configuration for alternate sources. Use tag `V-281336`. Source authority
requires manual confirmation; see `tests/V-281336.md` for evidence.

Dev currently overrides the list with `0.pool.ntp.org` through `3.pool.ntp.org`
as a temporary user-authorized choice. Public sources do not satisfy the DoW
authority requirement; native evaluation returns NR, not a compliance pass.

## Using the Evaluate-STIG AnswerFile

The role includes an optional answer file at
[`roles/rhel10-stig/files/RHEL10_Answerfile.xml`](roles/rhel10-stig/files/RHEL10_Answerfile.xml).
**It is not deployed by default.** Running the remediation playbook does not
install or activate it for Evaluate-STIG scans.

The file provides validation code for selected evaluator limitations and comments
for controls requiring manual procedures or site approval. It was developed for
RHEL 10 STIG V1R3 and Evaluate-STIG 1.2610.1 and can be tailored to your
environment. Before use, review each entry's applicability, expected status,
validation code, resulting status, and comments. Update environment-specific
paths, accounts, assumptions, and procedures; remove entries that do not apply.
Adopt and document any referenced manual procedures and approvals in the site's
security plan before relying on those answers.

Stage the reviewed file in a dedicated AnswerFiles directory on the scanned host,
then pass that **directory**, rather than the XML filename, with `-AFPath`. For
example, after placing the file at `/root/stig-answerfiles/RHEL10_Answerfile.xml`,
run on that host (adjust the evaluator installation path as needed):

```bash
sudo pwsh -NoProfile -File /root/tools/evaluate-stig-1.2610.1/Src/Evaluate-STIG/Evaluate-STIG.ps1 \
  -SelectSTIG RHEL10 -AFPath /root/stig-answerfiles -AnswerKey DEFAULT \
  -Output Console -JSON
```

The included entries use the `DEFAULT` answer key. Review the resulting statuses
and comments against current system evidence, and revalidate tailored entries
when the benchmark, evaluator, or environment changes.

**Disclaimer:** The answer file is provided as a starting point, without any
guarantee of accuracy, completeness, or compliance for your environment. Answers
can change reported findings, and a `Not a Finding` result alone does not prove
that a control is satisfied. The system owner and assessor remain responsible
for validating the technical evidence, implementing documented procedures,
obtaining required approvals, and determining compliance. The file is not a
waiver, risk acceptance, or authorization to operate.
