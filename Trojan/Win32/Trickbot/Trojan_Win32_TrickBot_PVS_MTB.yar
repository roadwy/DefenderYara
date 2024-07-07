
rule Trojan_Win32_TrickBot_PVS_MTB{
	meta:
		description = "Trojan:Win32/TrickBot.PVS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_02_0 = {8a 4c 24 10 8b 84 24 90 01 04 02 d9 8a 14 06 81 e3 ff 00 00 00 8a 4c 1c 14 32 d1 88 14 06 8b 84 24 90 01 04 46 3b f0 90 00 } //2
		$a_00_1 = {8b 55 10 89 54 9e 08 8b 5d fc 03 da 23 d8 8a 54 9e 08 32 51 06 ff 4d f8 88 57 06 } //2
		$a_02_2 = {69 c9 d6 2f 00 00 8b 5c 24 10 81 c5 e8 68 74 01 89 2d 90 01 04 03 ce 89 ac 1f 11 e2 ff ff 0f b7 c9 39 15 90 01 04 90 09 06 00 8b 3d 90 00 } //2
		$a_00_3 = {8a 04 0b c7 44 24 28 d9 b5 31 0d 8b 5c 24 18 8a 24 3b 30 c4 8b 7c 24 1c 88 24 0f } //2
	condition:
		((#a_02_0  & 1)*2+(#a_00_1  & 1)*2+(#a_02_2  & 1)*2+(#a_00_3  & 1)*2) >=2
 
}