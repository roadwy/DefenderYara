
rule Trojan_BAT_FormBook_AFL_MTB{
	meta:
		description = "Trojan:BAT/FormBook.AFL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {08 11 07 07 11 07 9a 1f 10 28 90 01 03 0a 9c 11 07 17 58 13 07 90 00 } //01 00 
		$a_01_1 = {53 00 68 00 61 00 72 00 65 00 43 00 72 00 65 00 61 00 74 00 69 00 6f 00 6e 00 } //00 00 
	condition:
		any of ($a_*)
 
}