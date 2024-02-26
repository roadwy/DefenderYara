
rule Trojan_Win32_Emotet_CCFJ_MTB{
	meta:
		description = "Trojan:Win32/Emotet.CCFJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {01 c8 8b 40 90 01 01 89 45 90 01 01 8b 45 90 01 01 c1 e0 90 01 01 03 45 90 01 01 0f b7 40 90 01 01 89 45 90 01 01 8b 45 90 01 01 33 45 90 01 01 89 45 90 01 01 8b 45 90 01 01 03 45 90 01 01 89 45 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}