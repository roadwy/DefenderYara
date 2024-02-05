
rule Trojan_BAT_FormBook_IZFA_MTB{
	meta:
		description = "Trojan:BAT/FormBook.IZFA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {09 06 08 06 08 8e 69 5d 91 07 06 91 61 d2 } //01 00 
		$a_01_1 = {47 65 74 42 79 74 65 73 } //01 00 
		$a_01_2 = {54 6f 41 72 72 61 79 } //00 00 
	condition:
		any of ($a_*)
 
}