
rule Trojan_Win32_Formbook_VD_MTB{
	meta:
		description = "Trojan:Win32/Formbook.VD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 45 fc 8a 80 90 01 04 34 90 01 01 8b 55 90 01 01 03 55 90 01 01 88 02 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}