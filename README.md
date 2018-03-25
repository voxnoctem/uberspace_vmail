# VoxNoctem / uberspace\_vmail

`uberspace_vmail` is a sync utility to keep passwords in an Uberspace (or other VMailMgr instances) in sync with LDAP accounts.

**Attention:** This is written for an Uberspace v6, starting with v7 other mail management methods are used and this will most likely not work anymore.

## Usage

This tool requires you to use the [uberspaceMailAccount.ldif](uberspaceMailAccount.ldif) schema definition or a compliant one. The attributes defined in there are used to set up the mail accounts inside the `passwd.cdb` file in the Uberspace.

For more help see the source code or `uberspace_vmail --help`.
