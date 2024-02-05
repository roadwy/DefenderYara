
rule Trojan_Win32_Trickbot_Z_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.Z!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 5d 08 8b cb c1 e9 10 83 e1 3f 8b c1 8b d1 d1 e8 33 f6 0f b6 c0 46 23 c6 23 d6 c1 e0 04 c1 e2 05 0b d0 8b c1 c1 e8 02 0f b6 c0 23 c6 c1 e0 03 0b d0 8b c1 c1 e8 03 0f b6 c0 23 c6 c1 e0 02 0b d0 8b c1 c1 e8 04 0f b6 c0 23 c6 c1 e9 05 0b d0 0f b6 c1 23 c6 8d 7d e0 03 c0 6a 07 0b d0 33 c0 59 f3 ab d9 75 e0 8b 4d e4 8b c1 33 c2 83 e0 3f 33 c8 89 4d e4 d9 65 e0 } //01 00 
		$a_01_1 = {c1 eb 18 83 e3 3f 8b c3 8b cb d1 e8 23 ce 0f b6 c0 23 c6 c1 e1 05 c1 e0 04 0b c8 8b c3 c1 e8 02 0f b6 c0 23 c6 c1 e0 03 0b c8 8b c3 c1 e8 03 0f b6 c0 23 c6 c1 e0 02 0b c8 8b c3 c1 e8 04 0f b6 c0 23 c6 0b c8 c1 eb 05 0f b6 c3 23 c6 03 c0 5f 0b c8 39 35 60 71 2b 10 } //00 00 
	condition:
		any of ($a_*)
 
}