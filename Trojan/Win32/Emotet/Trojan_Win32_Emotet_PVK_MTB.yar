
rule Trojan_Win32_Emotet_PVK_MTB{
	meta:
		description = "Trojan:Win32/Emotet.PVK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 05 00 00 "
		
	strings :
		$a_00_0 = {02 5c 24 10 83 c6 01 0f b6 c3 8a 4c 04 1c 8b 44 24 18 30 4c 30 ff 3b b4 24 54 01 00 00 7c } //2
		$a_00_1 = {8a 02 8b 4d fc 03 4d f8 81 e1 ff 00 00 00 33 d2 8a 94 0d b8 fe ff ff 33 c2 8b 4d 08 03 4d ec 88 01 e9 } //2
		$a_02_2 = {8b d7 b8 a8 dd 00 00 8b ca b8 ff 01 00 00 03 c1 2d ff 01 00 00 a3 90 01 04 a1 90 01 04 8b 0d 90 01 04 89 08 90 00 } //2
		$a_02_3 = {8a 4c 10 03 8a d9 8a f9 80 e3 f0 c0 e1 06 0a 4c 10 02 80 e7 fc c0 e3 02 0a 1c 10 c0 e7 04 0a 7c 10 01 81 3d 90 01 04 be 00 00 00 88 8d fb fb ff ff 90 00 } //2
		$a_00_4 = {8b 55 e4 81 ea e8 03 00 00 89 55 e4 c1 45 8c 07 8b 45 8c 33 45 90 89 45 8c 8b 4d c8 8b 55 f8 8b 45 8c 89 04 8a } //2
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_02_2  & 1)*2+(#a_02_3  & 1)*2+(#a_00_4  & 1)*2) >=2
 
}