
rule Trojan_Win32_Zbot_WE_MTB{
	meta:
		description = "Trojan:Win32/Zbot.WE!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 5d b4 81 f3 b1 2b 3d 37 0f b6 0b 43 43 81 f3 b1 2b 3d 37 89 5d b4 b8 18 00 00 00 c1 c8 1d 3b c8 0f 82 b1 00 00 00 } //01 00 
		$a_01_1 = {8b 17 8b 4d ec c1 c9 15 03 f9 8b 07 c1 c0 1f 83 e0 15 03 d0 4e 89 13 b9 f8 1a 3d ce 81 f1 fc 1a 3d ce 03 d9 85 f6 0f 84 90 03 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}