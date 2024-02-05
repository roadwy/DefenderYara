
rule Trojan_Win32_Zbot_PVD_MTB{
	meta:
		description = "Trojan:Win32/Zbot.PVD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 05 00 00 02 00 "
		
	strings :
		$a_02_0 = {89 32 8b 95 90 01 02 ff ff 83 c2 03 89 95 90 01 02 ff ff 8b 95 90 01 02 ff ff 83 ea 04 89 95 90 01 02 ff ff 90 00 } //02 00 
		$a_00_1 = {8b bd 14 fe ff ff 30 14 39 83 fb 30 7e } //02 00 
		$a_02_2 = {03 c1 8a 4c 24 10 03 c6 8a 10 32 d1 88 10 90 09 06 00 8b 0d 90 00 } //02 00 
		$a_00_3 = {8a 4c 2b 03 8a d1 88 4c 24 10 80 e2 f0 c0 e2 02 0a 14 2b 88 54 24 12 3d e9 05 00 00 0f 84 } //02 00 
		$a_02_4 = {8b ca b8 9a 02 00 00 03 c1 2d 9a 02 00 00 a3 90 01 04 a1 90 01 04 8b 0d 90 01 04 89 08 90 09 07 00 8b d7 b8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}