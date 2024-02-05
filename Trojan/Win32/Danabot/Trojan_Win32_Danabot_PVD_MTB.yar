
rule Trojan_Win32_Danabot_PVD_MTB{
	meta:
		description = "Trojan:Win32/Danabot.PVD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_02_0 = {8b 44 24 24 8b 8c 24 40 08 00 00 5f 5e 89 68 04 5d 89 18 5b 33 cc e8 90 01 04 81 c4 34 08 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}