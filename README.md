# wg-ldap

`wg-ldap` is designed to more easily distribute your wireguard settings over multiple machines.
Instead of manually copying over or editing various files for `wg-quick`, `wg-ldap` stores the configuration in an LDAP server instead.

## LDAP schema and example

The file `wg-schema.ldif` contains the schema to import into your LDAP server, in OpenLDAP cn=config-style.
With appropriate permissions, you can simply add the schema using `ldapadd`.

The file `wg-example.ldif` contains some sample entries, which `wg-ldap` should be able to load.

NOTE: The oids used in `wg-schema.ldif` are placeholders, and have not been registered.