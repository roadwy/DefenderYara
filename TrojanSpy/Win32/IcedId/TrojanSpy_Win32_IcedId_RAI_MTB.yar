
rule TrojanSpy_Win32_IcedId_RAI_MTB{
	meta:
		description = "TrojanSpy:Win32/IcedId.RAI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {b8 3b 2d 0b 00 01 45 fc 8b 45 fc 8a 04 08 88 04 0a } //01 00 
		$a_01_1 = {81 c7 d4 2d 0a 01 03 c8 } //01 00 
		$a_01_2 = {8a c3 80 ea 06 fe c8 f6 ea 89 7d 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanSpy_Win32_IcedId_RAI_MTB_2{
	meta:
		description = "TrojanSpy:Win32/IcedId.RAI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 08 00 00 05 00 "
		
	strings :
		$a_03_0 = {81 c1 f8 7a 0c 01 90 02 05 83 c7 04 90 02 1f 75 90 0a 3f 00 03 35 90 01 04 89 35 90 00 } //02 00 
		$a_03_1 = {8b 0f 81 fa 90 01 04 75 90 02 1f 03 35 90 01 04 89 35 90 00 } //05 00 
		$a_03_2 = {81 c7 cc cc 04 01 90 02 05 89 38 90 02 05 90 02 3f 0f 90 00 } //02 00 
		$a_03_3 = {2b f0 8b 44 24 1c 1b da 8b 38 81 fe 90 01 04 75 90 02 2f 0f b7 05 90 00 } //05 00 
		$a_01_4 = {81 c7 b0 8d 07 01 03 f2 89 38 } //02 00 
		$a_03_5 = {03 c1 89 44 24 1c 8d 04 3e 90 0a 1f 00 05 90 00 } //05 00 
		$a_01_6 = {8b 07 05 b4 50 0a 01 89 07 83 c7 04 } //02 00 
		$a_01_7 = {0f b7 06 2b c8 8a c1 8a d1 02 c0 02 d0 02 d3 88 15 } //00 00 
	condition:
		any of ($a_*)
 
}