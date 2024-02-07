
rule Trojan_Win32_Trickbot_DHS_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.DHS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {0f b6 c3 03 c1 b9 15 e0 00 00 99 f7 f9 8b 85 90 01 04 8a 8c 15 90 01 04 30 4f ff 90 00 } //01 00 
		$a_81_1 = {74 52 59 51 69 67 61 61 30 72 6a 61 6f 4d 32 4c 62 34 61 4f 31 69 47 53 44 72 46 4c 76 50 30 41 4c 46 48 4e 30 } //00 00  tRYQigaa0rjaoM2Lb4aO1iGSDrFLvP0ALFHN0
	condition:
		any of ($a_*)
 
}