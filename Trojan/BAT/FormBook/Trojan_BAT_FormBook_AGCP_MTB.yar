
rule Trojan_BAT_FormBook_AGCP_MTB{
	meta:
		description = "Trojan:BAT/FormBook.AGCP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {0a 06 1c 8d 17 00 00 01 25 16 72 67 00 00 70 a2 25 17 72 6d 00 00 70 a2 25 18 72 73 00 00 70 a2 25 19 } //01 00 
		$a_01_1 = {53 00 74 00 75 00 70 00 69 00 64 00 } //00 00 
	condition:
		any of ($a_*)
 
}