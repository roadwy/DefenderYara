
rule Trojan_Win32_AccountDiscovery_E{
	meta:
		description = "Trojan:Win32/AccountDiscovery.E,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 05 00 00 "
		
	strings :
		$a_00_0 = {63 00 6d 00 64 00 6b 00 65 00 79 00 } //1 cmdkey
		$a_00_1 = {76 00 61 00 75 00 6c 00 74 00 63 00 6d 00 64 00 } //1 vaultcmd
		$a_00_2 = {2e 00 6e 00 65 00 74 00 } //65535 .net
		$a_00_3 = {2f 00 61 00 64 00 64 00 } //65535 /add
		$a_00_4 = {2f 00 64 00 65 00 6c 00 65 00 74 00 65 00 } //65535 /delete
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*65535+(#a_00_3  & 1)*65535+(#a_00_4  & 1)*65535) >=1
 
}