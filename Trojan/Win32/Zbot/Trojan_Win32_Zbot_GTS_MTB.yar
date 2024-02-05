
rule Trojan_Win32_Zbot_GTS_MTB{
	meta:
		description = "Trojan:Win32/Zbot.GTS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,17 00 17 00 05 00 00 0a 00 "
		
	strings :
		$a_01_0 = {8b 75 08 8b 7d fc 8b 4d 0c c1 e9 02 f3 a5 8b 55 fc 03 52 3c 89 95 68 ff ff ff 66 f7 42 16 00 20 74 0e } //0a 00 
		$a_01_1 = {51 8b 48 10 8b 70 14 8b 78 0c 03 75 fc 03 7d f8 f3 a4 59 83 c0 28 e2 e8 } //01 00 
		$a_80_2 = {4c 69 70 65 72 63 6b } //Liperck  01 00 
		$a_80_3 = {62 72 6f 6e 69 6b 63 } //bronikc  01 00 
		$a_80_4 = {65 64 69 6e 61 6c 72 64 6f } //edinalrdo  00 00 
	condition:
		any of ($a_*)
 
}