
rule Trojan_Win32_Trickbot_UG_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.UG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {53 8b ce e8 90 02 04 8b 90 01 03 8b f8 8b 90 01 01 83 e0 90 01 01 50 e8 90 02 04 8a 90 01 01 30 90 01 01 8b 90 01 02 2b 90 01 02 43 3b 90 01 01 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}