
rule Trojan_Win32_Formbook_RPX_MTB{
	meta:
		description = "Trojan:Win32/Formbook.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8a 11 88 55 fe 0f b6 45 ff c1 f8 03 0f b6 4d ff c1 e1 05 0b c1 0f b6 55 fe 33 c2 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Formbook_RPX_MTB_2{
	meta:
		description = "Trojan:Win32/Formbook.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8a 00 88 45 fe 0f b6 45 ff c1 f8 03 0f b6 4d ff c1 e1 05 0b c1 0f b6 4d fe 33 c1 8b 4d f8 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Formbook_RPX_MTB_3{
	meta:
		description = "Trojan:Win32/Formbook.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {88 55 ff 8b 45 d8 03 45 f0 8a 08 88 4d fe 0f b6 55 ff c1 fa 03 0f b6 45 ff c1 e0 05 0b d0 0f b6 4d fe 33 d1 8b 45 f8 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Formbook_RPX_MTB_4{
	meta:
		description = "Trojan:Win32/Formbook.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8a 11 88 55 fe 0f b6 45 ff c1 f8 03 0f b6 4d ff c1 e1 05 0b c1 0f b6 55 fe 33 c2 8b 4d f0 03 4d f4 88 01 8b 45 e8 83 c0 01 99 } //00 00 
	condition:
		any of ($a_*)
 
}