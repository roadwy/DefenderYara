
rule Trojan_BAT_FormBook_NFA_MTB{
	meta:
		description = "Trojan:BAT/FormBook.NFA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {02 28 40 00 00 0a 0a 28 90 01 03 0a 06 28 90 01 03 06 6f 90 01 03 0a 0b 2b 00 07 2a 90 00 } //01 00 
		$a_01_1 = {61 6e 64 72 6f 5a 69 64 } //00 00  androZid
	condition:
		any of ($a_*)
 
}