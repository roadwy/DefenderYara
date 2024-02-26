
rule Trojan_Win32_Zusy_RG_MTB{
	meta:
		description = "Trojan:Win32/Zusy.RG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b c3 0f 43 cf 33 d2 f7 74 24 90 01 01 8a 04 0a 30 04 33 43 a1 90 01 04 8b 35 90 01 04 2b c6 3b d8 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Zusy_RG_MTB_2{
	meta:
		description = "Trojan:Win32/Zusy.RG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {83 65 fc 00 8b c6 8a 96 90 01 03 00 83 e0 03 6a 00 88 55 bf 8a 88 90 01 03 00 32 ca 8d 04 11 88 86 90 01 03 00 e8 90 01 04 8a 45 bf 28 86 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}