
rule Trojan_BAT_FormBook_EUJ_MTB{
	meta:
		description = "Trojan:BAT/FormBook.EUJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {02 03 66 5f 02 66 03 5f 60 90 01 05 0a 06 2a 90 00 } //01 00 
		$a_01_1 = {51 00 50 00 56 00 4d 00 65 00 74 00 68 00 6f 00 64 00 30 00 51 00 50 00 56 00 } //01 00  QPVMethod0QPV
		$a_01_2 = {47 65 74 4d 65 74 68 6f 64 } //01 00  GetMethod
		$a_01_3 = {47 65 74 54 79 70 65 } //00 00  GetType
	condition:
		any of ($a_*)
 
}