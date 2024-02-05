
rule Trojan_BAT_FormBook_AGCF_MTB{
	meta:
		description = "Trojan:BAT/FormBook.AGCF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {16 13 06 2b 15 07 11 06 06 11 06 9a 1f 10 28 90 01 03 0a 9c 11 06 17 58 90 00 } //01 00 
		$a_01_1 = {49 6d 70 61 63 74 61 2e 41 6c 75 6e 6f 73 2e 55 49 } //00 00 
	condition:
		any of ($a_*)
 
}