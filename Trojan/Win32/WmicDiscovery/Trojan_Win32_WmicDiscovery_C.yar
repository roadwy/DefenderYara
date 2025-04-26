
rule Trojan_Win32_WmicDiscovery_C{
	meta:
		description = "Trojan:Win32/WmicDiscovery.C,SIGNATURE_TYPE_CMDHSTR_EXT,64 00 14 00 02 00 00 "
		
	strings :
		$a_00_0 = {57 00 4d 00 49 00 43 00 2e 00 65 00 78 00 65 00 } //10 WMIC.exe
		$a_00_1 = {75 00 73 00 65 00 72 00 61 00 63 00 63 00 6f 00 75 00 6e 00 74 00 20 00 67 00 65 00 74 00 20 00 2f 00 41 00 4c 00 4c 00 } //10 useraccount get /ALL
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10) >=20
 
}