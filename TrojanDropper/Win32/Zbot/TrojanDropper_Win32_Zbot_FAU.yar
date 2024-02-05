
rule TrojanDropper_Win32_Zbot_FAU{
	meta:
		description = "TrojanDropper:Win32/Zbot.FAU,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {70 69 73 67 72 72 6f } //01 00 
		$a_03_1 = {0f b6 08 8b 90 01 02 8b 45 08 8b 14 90 90 d3 ea a1 90 01 04 0f b6 08 b8 90 01 04 2b c1 8b 90 01 02 8b 75 08 8b 34 8e 8b c8 d3 e6 0b d6 8b 90 01 02 8b 4d 10 89 14 81 01 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}