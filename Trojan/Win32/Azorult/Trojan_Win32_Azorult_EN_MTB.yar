
rule Trojan_Win32_Azorult_EN_MTB{
	meta:
		description = "Trojan:Win32/Azorult.EN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 07 00 "
		
	strings :
		$a_01_0 = {81 00 e1 34 ef c6 c3 29 08 c3 01 08 c3 01 08 c3 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Azorult_EN_MTB_2{
	meta:
		description = "Trojan:Win32/Azorult.EN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_01_0 = {8b 04 24 89 c3 03 5c 24 08 89 5c 24 14 8b 54 24 10 8b 44 24 14 8a 1a 8a 38 30 fb 88 1a } //00 00 
	condition:
		any of ($a_*)
 
}