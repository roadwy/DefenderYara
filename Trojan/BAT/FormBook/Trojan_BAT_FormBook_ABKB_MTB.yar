
rule Trojan_BAT_FormBook_ABKB_MTB{
	meta:
		description = "Trojan:BAT/FormBook.ABKB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 04 00 "
		
	strings :
		$a_03_0 = {08 07 17 8d 90 01 03 01 25 16 06 8c 90 01 03 01 a2 14 28 90 01 03 0a 28 90 01 03 0a 1f 10 28 90 01 03 0a 6f 90 01 03 0a 06 90 00 } //01 00 
		$a_01_1 = {50 6f 6e 74 6f 6f 6e 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //00 00 
	condition:
		any of ($a_*)
 
}