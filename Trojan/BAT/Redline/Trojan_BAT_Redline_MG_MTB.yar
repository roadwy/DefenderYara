
rule Trojan_BAT_Redline_MG_MTB{
	meta:
		description = "Trojan:BAT/Redline.MG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 05 00 "
		
	strings :
		$a_01_0 = {06 7e 29 00 00 04 06 91 20 34 03 00 00 59 d2 9c 00 06 17 58 0a 06 7e 29 00 00 04 8e 69 fe 04 0b 07 2d d7 } //01 00 
		$a_01_1 = {49 4a 4f 41 46 49 46 48 } //01 00  IJOAFIFH
		$a_01_2 = {49 4a 55 41 44 46 57 46 } //01 00  IJUADFWF
		$a_01_3 = {62 61 7a 61 2e 50 72 6f 70 65 72 74 69 65 73 } //00 00  baza.Properties
	condition:
		any of ($a_*)
 
}