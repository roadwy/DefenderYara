
rule HackTool_Linux_SuspiciousKerberosCredentialAccess_A{
	meta:
		description = "HackTool:Linux/SuspiciousKerberosCredentialAccess.A,SIGNATURE_TYPE_CMDHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_00_0 = {63 00 61 00 74 00 20 00 2f 00 74 00 6d 00 70 00 2f 00 6b 00 72 00 62 00 35 00 2e 00 6b 00 65 00 79 00 74 00 61 00 62 00 } //00 00  cat /tmp/krb5.keytab
	condition:
		any of ($a_*)
 
}