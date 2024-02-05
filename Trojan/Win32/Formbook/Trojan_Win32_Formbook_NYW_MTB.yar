
rule Trojan_Win32_Formbook_NYW_MTB{
	meta:
		description = "Trojan:Win32/Formbook.NYW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8a 04 37 04 04 34 dc 04 23 34 cd 04 5d 34 86 2c 17 34 e1 2c 6f 88 04 37 46 3b f3 72 } //00 00 
	condition:
		any of ($a_*)
 
}