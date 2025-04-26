
rule TrojanSpy_Win32_IcedId_RAI_MTB{
	meta:
		description = "TrojanSpy:Win32/IcedId.RAI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {b8 3b 2d 0b 00 01 45 fc 8b 45 fc 8a 04 08 88 04 0a } //2
		$a_01_1 = {81 c7 d4 2d 0a 01 03 c8 } //1
		$a_01_2 = {8a c3 80 ea 06 fe c8 f6 ea 89 7d 00 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}
rule TrojanSpy_Win32_IcedId_RAI_MTB_2{
	meta:
		description = "TrojanSpy:Win32/IcedId.RAI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 08 00 00 "
		
	strings :
		$a_03_0 = {81 c1 f8 7a 0c 01 [0-05] 83 c7 04 [0-1f] 75 90 0a 3f 00 03 35 ?? ?? ?? ?? 89 35 } //5
		$a_03_1 = {8b 0f 81 fa ?? ?? ?? ?? 75 [0-1f] 03 35 ?? ?? ?? ?? 89 35 } //2
		$a_03_2 = {81 c7 cc cc 04 01 [0-05] 89 38 [0-05] [0-3f] 0f } //5
		$a_03_3 = {2b f0 8b 44 24 1c 1b da 8b 38 81 fe ?? ?? ?? ?? 75 [0-2f] 0f b7 05 } //2
		$a_01_4 = {81 c7 b0 8d 07 01 03 f2 89 38 } //5
		$a_03_5 = {03 c1 89 44 24 1c 8d 04 3e 90 0a 1f 00 05 } //2
		$a_01_6 = {8b 07 05 b4 50 0a 01 89 07 83 c7 04 } //5
		$a_01_7 = {0f b7 06 2b c8 8a c1 8a d1 02 c0 02 d0 02 d3 88 15 } //2
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*2+(#a_03_2  & 1)*5+(#a_03_3  & 1)*2+(#a_01_4  & 1)*5+(#a_03_5  & 1)*2+(#a_01_6  & 1)*5+(#a_01_7  & 1)*2) >=7
 
}