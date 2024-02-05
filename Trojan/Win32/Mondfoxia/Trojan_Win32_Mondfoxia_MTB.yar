
rule Trojan_Win32_Mondfoxia_MTB{
	meta:
		description = "Trojan:Win32/Mondfoxia!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b 45 fc 8d 34 03 e8 90 01 04 30 06 b8 90 01 04 29 45 90 01 01 39 7d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Mondfoxia_MTB_2{
	meta:
		description = "Trojan:Win32/Mondfoxia!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {8d 34 18 e8 90 01 04 30 06 b8 90 01 04 29 85 90 01 04 8b 85 90 01 04 85 c0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}