
rule Trojan_Win32_IcedId_SIBJ13_MTB{
	meta:
		description = "Trojan:Win32/IcedId.SIBJ13!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {63 68 69 65 66 4c 65 67 2e 70 64 62 } //01 00 
		$a_03_1 = {89 3e 83 c6 04 90 02 10 83 6c 24 90 01 01 01 89 74 24 90 01 01 90 18 90 02 60 8b 54 24 90 1b 02 8b 3a 90 02 50 8b 74 24 90 1b 02 81 c7 90 01 04 90 02 10 89 3e 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_IcedId_SIBJ13_MTB_2{
	meta:
		description = "Trojan:Win32/IcedId.SIBJ13!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {73 74 6f 6f 64 2e 70 64 62 } //01 00 
		$a_03_1 = {83 c5 04 0f 90 02 10 81 fd 90 01 04 73 90 01 01 90 02 10 90 18 90 02 60 8b 3d 90 01 04 90 02 20 8b b4 2f 90 01 04 90 02 30 81 c6 90 01 04 90 02 10 89 b4 90 01 04 90 02 10 83 c5 04 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}