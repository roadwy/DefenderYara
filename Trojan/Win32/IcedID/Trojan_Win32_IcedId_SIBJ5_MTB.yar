
rule Trojan_Win32_IcedId_SIBJ5_MTB{
	meta:
		description = "Trojan:Win32/IcedId.SIBJ5!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {42 6f 64 79 90 02 05 57 6f 72 6c 64 2e 70 64 62 90 00 } //01 00 
		$a_03_1 = {8b 7d 00 a3 90 02 3a 81 c7 a4 6f 01 01 89 7d 00 90 02 1a 83 c5 04 83 6c 24 90 01 01 01 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_IcedId_SIBJ5_MTB_2{
	meta:
		description = "Trojan:Win32/IcedId.SIBJ5!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {4b 00 6e 00 65 00 77 00 2e 00 64 00 6c 00 6c 00 } //01 00  Knew.dll
		$a_03_1 = {57 c7 44 24 90 01 01 90 01 04 90 02 8b 7c 24 90 01 01 90 02 8b 35 90 01 04 90 02 8d bc 3e 90 01 04 8b 37 90 02 83 44 24 90 1b 03 04 90 02 81 c6 8c 48 06 01 81 7c 24 90 1b 03 90 01 04 90 02 89 37 90 02 0f 82 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}