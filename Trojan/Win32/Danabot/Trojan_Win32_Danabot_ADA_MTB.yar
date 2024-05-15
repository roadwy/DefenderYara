
rule Trojan_Win32_Danabot_ADA_MTB{
	meta:
		description = "Trojan:Win32/Danabot.ADA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {33 d2 f7 f3 8b d0 6b c2 64 2b f8 8b c7 8b fa 83 ee 02 8b 04 85 d2 df 88 00 8b d6 03 d2 03 d1 89 02 } //00 00 
	condition:
		any of ($a_*)
 
}