
rule Trojan_BAT_FormBook_EWE_MTB{
	meta:
		description = "Trojan:BAT/FormBook.EWE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {09 11 05 06 11 05 06 90 01 05 5d 90 01 05 09 11 05 91 61 d2 9c 00 11 05 17 58 13 05 90 00 } //01 00 
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 } //00 00  FromBase64
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_FormBook_EWE_MTB_2{
	meta:
		description = "Trojan:BAT/FormBook.EWE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {09 11 05 06 11 05 06 90 01 05 5d 90 01 05 09 11 05 91 61 d2 9c 00 11 05 17 58 13 05 90 00 } //01 00 
		$a_01_1 = {4b 00 4c 00 57 00 4f 00 31 00 36 00 55 00 4b 00 51 00 43 00 55 00 32 00 41 00 50 00 52 00 } //00 00  KLWO16UKQCU2APR
	condition:
		any of ($a_*)
 
}