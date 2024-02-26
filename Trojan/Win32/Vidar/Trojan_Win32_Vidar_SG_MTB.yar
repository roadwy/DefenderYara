
rule Trojan_Win32_Vidar_SG_MTB{
	meta:
		description = "Trojan:Win32/Vidar.SG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 45 08 f7 f1 8b 45 fc 68 90 01 04 8a 0c 02 8b 55 08 03 d6 8a 04 13 32 c1 88 02 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Vidar_SG_MTB_2{
	meta:
		description = "Trojan:Win32/Vidar.SG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8a 04 02 32 04 39 88 07 ff d6 68 90 01 04 ff d6 68 90 01 04 ff d6 8b 7d 90 01 01 43 3b 5d 90 01 01 72 a2 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}