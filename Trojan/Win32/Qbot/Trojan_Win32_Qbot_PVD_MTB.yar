
rule Trojan_Win32_Qbot_PVD_MTB{
	meta:
		description = "Trojan:Win32/Qbot.PVD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_02_0 = {69 d2 fd 43 03 00 89 15 90 01 04 81 05 90 01 04 c3 9e 26 00 a0 90 01 04 30 04 1e 46 3b f7 7c 90 09 06 00 8b 15 90 00 } //2
		$a_02_1 = {8b d7 b8 b9 5e 01 00 8b ca b8 ff 01 00 00 03 c1 2d ff 01 00 00 a3 90 01 04 a1 90 01 04 8b 0d 90 01 04 89 08 90 00 } //2
		$a_00_2 = {8a 4c 24 14 8b 84 24 c0 02 00 00 02 d9 81 e3 ff 00 00 00 8a 54 1c 18 8a 1c 07 32 da 88 1c 07 8b 84 24 c4 02 00 00 47 3b f8 0f 8c } //2
		$a_00_3 = {8a 1c 0e 8b 4c 24 1c 8b 3c 24 32 1c 39 c6 44 24 4b e1 8b 4c 24 18 88 1c 39 83 c7 01 8b 4c 24 04 89 4c 24 34 } //2
	condition:
		((#a_02_0  & 1)*2+(#a_02_1  & 1)*2+(#a_00_2  & 1)*2+(#a_00_3  & 1)*2) >=2
 
}