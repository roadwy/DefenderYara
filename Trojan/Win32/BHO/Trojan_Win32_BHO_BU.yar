
rule Trojan_Win32_BHO_BU{
	meta:
		description = "Trojan:Win32/BHO.BU,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 6f 75 6e 74 3d 25 73 26 64 61 74 61 3d 25 73 26 63 6f 70 79 3d 25 73 26 69 6e 66 6f 3d 25 73 } //01 00  count=%s&data=%s&copy=%s&info=%s
		$a_01_1 = {72 65 67 73 76 72 33 32 20 2f 73 20 25 73 } //01 00  regsvr32 /s %s
		$a_01_2 = {44 6c 6c 56 61 6e 69 73 68 } //01 00  DllVanish
		$a_01_3 = {53 00 65 00 44 00 65 00 62 00 75 00 67 00 50 00 72 00 69 00 76 00 69 00 6c 00 65 00 67 00 65 00 } //01 00  SeDebugPrivilege
		$a_01_4 = {5c 73 79 73 74 65 6d 33 32 5c 64 6c 6c 63 61 63 68 65 } //00 00  \system32\dllcache
	condition:
		any of ($a_*)
 
}