
rule Trojan_Win32_Qakbot_SAO_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.SAO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {99 f7 7d e4 33 55 90 01 01 89 55 90 01 01 8b 55 90 01 01 03 55 90 01 01 0f b6 02 8b 4d 90 01 01 03 4d 90 01 01 0f b6 11 33 d0 8b 45 90 01 01 03 45 90 01 01 88 90 00 } //01 00 
		$a_00_1 = {56 69 73 69 62 6c 65 45 6e 74 72 79 } //01 00  VisibleEntry
		$a_00_2 = {74 6f 78 69 63 6f 6c 6f 67 69 63 } //00 00  toxicologic
	condition:
		any of ($a_*)
 
}