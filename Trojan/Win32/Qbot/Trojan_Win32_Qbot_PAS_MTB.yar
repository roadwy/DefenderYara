
rule Trojan_Win32_Qbot_PAS_MTB{
	meta:
		description = "Trojan:Win32/Qbot.PAS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {03 c2 89 45 a0 68 90 01 04 e8 90 01 04 03 45 90 01 01 8b 55 90 01 01 33 02 89 45 90 01 01 68 90 01 04 e8 90 01 04 03 45 90 01 01 8b 55 90 01 01 89 02 8b 45 90 01 01 83 c0 04 89 45 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}