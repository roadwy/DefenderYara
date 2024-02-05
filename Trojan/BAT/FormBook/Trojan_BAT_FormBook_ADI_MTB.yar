
rule Trojan_BAT_FormBook_ADI_MTB{
	meta:
		description = "Trojan:BAT/FormBook.ADI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {06 0b 16 0c 2b 49 00 16 0d 2b 31 00 07 08 09 28 } //01 00 
		$a_01_1 = {50 00 69 00 6e 00 6b 00 } //01 00 
		$a_01_2 = {44 35 32 38 34 37 33 35 32 33 34 35 } //00 00 
	condition:
		any of ($a_*)
 
}