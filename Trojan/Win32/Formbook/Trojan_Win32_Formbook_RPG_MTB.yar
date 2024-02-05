
rule Trojan_Win32_Formbook_RPG_MTB{
	meta:
		description = "Trojan:Win32/Formbook.RPG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {8a 04 19 2c 90 01 01 34 90 01 01 2c 90 01 01 34 90 01 01 2c 90 01 01 34 90 01 01 88 04 19 41 3b cf 72 e9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}