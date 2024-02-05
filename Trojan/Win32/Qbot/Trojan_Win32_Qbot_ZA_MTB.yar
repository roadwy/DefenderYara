
rule Trojan_Win32_Qbot_ZA_MTB{
	meta:
		description = "Trojan:Win32/Qbot.ZA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b 4d 08 89 31 68 90 01 04 ff 15 90 01 03 00 05 90 01 04 8b 55 08 8b 0a 2b c8 8b 55 08 89 0a 5e 8b e5 5d c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qbot_ZA_MTB_2{
	meta:
		description = "Trojan:Win32/Qbot.ZA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {03 f0 68 03 90 01 03 ff 15 90 01 04 03 f0 68 90 01 04 ff 15 90 01 04 03 f0 8b 55 08 8b 02 2b c6 8b 4d 08 89 01 5e 8b e5 5d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}