
rule Trojan_Win32_Pikabot_YV_MTB{
	meta:
		description = "Trojan:Win32/Pikabot.YV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {03 c3 89 45 f0 90 13 8b 45 f0 33 d2 90 13 b9 90 01 04 83 c1 90 01 01 90 13 f7 f1 8b 45 d8 90 13 89 94 85 90 01 04 90 13 8b 45 d8 90 13 40 89 45 d8 90 13 8b 45 d8 3b 45 d4 7d 90 01 01 90 13 69 45 f0 90 01 04 bb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}