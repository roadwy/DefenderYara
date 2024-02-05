
rule Trojan_Win32_Formbook_RPX_MTB{
	meta:
		description = "Trojan:Win32/Formbook.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8a 11 88 55 fe 0f b6 45 ff c1 f8 03 0f b6 4d ff c1 e1 05 0b c1 0f b6 55 fe 33 c2 8b 4d f0 03 4d f4 88 01 8b 45 e8 83 c0 01 99 } //00 00 
	condition:
		any of ($a_*)
 
}