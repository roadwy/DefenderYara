
rule Trojan_Win32_Zbot_DP_MTB{
	meta:
		description = "Trojan:Win32/Zbot.DP!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {56 57 53 8b 5d 94 85 df c1 c3 18 8b 0b 8b 45 80 85 c3 c1 c8 02 3b c8 75 cb } //01 00 
		$a_01_1 = {8b 0e 03 cb b8 00 40 00 00 c1 c0 14 03 f0 c1 c1 08 89 4d 94 03 d5 52 e8 90 01 04 56 59 5a 2b d5 8b 45 a8 85 c7 c1 c0 16 03 c2 3b c2 0f 85 90 01 04 2b c2 4a 3b d0 75 c6 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}