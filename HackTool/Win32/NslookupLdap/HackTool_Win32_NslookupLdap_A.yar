
rule HackTool_Win32_NslookupLdap_A{
	meta:
		description = "HackTool:Win32/NslookupLdap.A,SIGNATURE_TYPE_CMDHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {6e 00 73 00 6c 00 6f 00 6f 00 6b 00 75 00 70 00 } //1 nslookup
		$a_00_1 = {2d 00 71 00 75 00 65 00 72 00 79 00 74 00 79 00 70 00 65 00 3d 00 61 00 6c 00 6c 00 } //1 -querytype=all
		$a_00_2 = {2d 00 74 00 69 00 6d 00 65 00 6f 00 75 00 74 00 3d 00 } //1 -timeout=
		$a_00_3 = {5f 00 6c 00 64 00 61 00 70 00 2e 00 5f 00 74 00 63 00 70 00 2e 00 64 00 63 00 2e 00 5f 00 6d 00 73 00 64 00 63 00 73 00 2e 00 } //1 _ldap._tcp.dc._msdcs.
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}