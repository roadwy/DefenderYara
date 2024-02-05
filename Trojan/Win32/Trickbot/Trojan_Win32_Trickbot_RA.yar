
rule Trojan_Win32_Trickbot_RA{
	meta:
		description = "Trojan:Win32/Trickbot.RA,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_02_0 = {57 8b ec 8b c7 05 90 01 04 68 f1 ff 00 00 59 89 45 04 8b d7 8b f7 49 8b c1 66 ad 85 c0 74 90 00 } //01 00 
		$a_02_1 = {57 8b ec 05 90 01 04 89 45 04 68 f0 ff 00 00 59 8b f7 8b d7 fc 8b c1 66 ad 85 c0 74 90 00 } //01 00 
		$a_00_2 = {51 8b c6 8b 00 46 8b 0f 33 c8 8b c1 88 07 47 4b 58 8b c8 75 06 58 2b f0 50 8b d8 49 75 } //00 00 
	condition:
		any of ($a_*)
 
}