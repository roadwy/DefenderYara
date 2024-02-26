
rule Trojan_BAT_Redline_MG_MTB{
	meta:
		description = "Trojan:BAT/Redline.MG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {13 09 16 13 0a 2b 22 11 09 11 0a 9a 13 0b 00 06 11 0b 6f 90 01 03 06 13 0c 11 0c 2c 05 00 17 0d 2b 0f 00 11 0a 17 58 13 0a 11 0a 11 09 8e 69 32 d6 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_Redline_MG_MTB_2{
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