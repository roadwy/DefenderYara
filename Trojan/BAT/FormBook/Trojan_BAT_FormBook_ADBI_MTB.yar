
rule Trojan_BAT_FormBook_ADBI_MTB{
	meta:
		description = "Trojan:BAT/FormBook.ADBI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {09 11 04 28 90 01 03 06 13 05 11 05 28 90 01 03 06 13 06 07 06 11 06 d2 9c 00 11 04 17 58 90 00 } //01 00 
		$a_01_1 = {43 00 6f 00 72 00 65 00 41 00 73 00 73 00 69 00 67 00 6e 00 } //00 00  CoreAssign
	condition:
		any of ($a_*)
 
}