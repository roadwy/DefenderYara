
rule Trojan_Win32_Smokeloader_HNE_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.HNE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {ee 3d ea f4 90 03 01 01 89 8b 90 09 a0 00 90 02 a0 02 00 00 00 83 90 02 03 03 90 02 20 c1 e0 04 90 02 30 89 90 02 60 8b 90 02 30 c7 05 90 01 04 ee 3d ea f4 90 02 b0 c1 e0 04 90 02 40 d3 e8 90 02 30 8b 90 02 30 8b 90 02 30 90 17 02 01 01 0f e9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Smokeloader_HNE_MTB_2{
	meta:
		description = "Trojan:Win32/Smokeloader.HNE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {03 45 f0 8b 4d d8 03 4d f0 8a 09 88 08 81 } //01 00 
		$a_01_1 = {00 00 00 00 6b 00 65 00 72 00 6e 00 65 00 6c 00 33 00 32 00 2e 00 64 00 6c 00 6c 00 00 00 00 00 20 25 73 20 25 64 20 25 66 00 00 00 6b 65 72 6e 65 6c 33 32 2e 64 6c 6c 00 00 00 00 } //01 00 
		$a_01_2 = {03 55 e4 8b 45 f0 31 45 fc 33 55 fc } //01 00 
		$a_03_3 = {29 45 f4 83 6d f4 90 09 04 00 83 45 f4 90 01 01 29 45 f4 83 6d f4 90 1b 01 90 00 } //01 00 
		$a_03_4 = {8b d7 d3 ea 8d 04 3b 89 45 90 01 01 c7 05 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}