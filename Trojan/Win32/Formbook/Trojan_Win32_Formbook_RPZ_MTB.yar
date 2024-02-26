
rule Trojan_Win32_Formbook_RPZ_MTB{
	meta:
		description = "Trojan:Win32/Formbook.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {b8 ab aa aa 2a f7 eb c1 fa 02 8b da c1 eb 1f 03 da 75 ed } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Formbook_RPZ_MTB_2{
	meta:
		description = "Trojan:Win32/Formbook.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 55 fc 83 c2 01 89 55 fc 81 7d fc 7f 17 00 00 7d 27 8b 45 fc 99 b9 0c 00 00 00 f7 f9 8b 45 ec 0f b6 0c 10 8b 55 f8 03 55 fc 0f b6 02 33 c1 8b 4d f8 03 4d fc 88 01 eb c7 } //00 00 
	condition:
		any of ($a_*)
 
}