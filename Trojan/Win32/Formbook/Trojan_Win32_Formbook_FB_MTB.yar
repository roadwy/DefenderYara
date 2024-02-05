
rule Trojan_Win32_Formbook_FB_MTB{
	meta:
		description = "Trojan:Win32/Formbook.FB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {55 8b ec 51 a1 90 01 04 8b 08 8b 15 90 01 04 8b 04 91 2d 90 01 03 00 89 45 fc 8b 0d 90 01 04 83 c1 01 89 0d 90 01 04 8b 45 fc 8b e5 5d c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}