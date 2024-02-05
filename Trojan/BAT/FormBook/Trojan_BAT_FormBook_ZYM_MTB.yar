
rule Trojan_BAT_FormBook_ZYM_MTB{
	meta:
		description = "Trojan:BAT/FormBook.ZYM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {2b 11 06 07 06 07 91 20 90 01 03 00 59 d2 9c 07 17 58 90 00 } //01 00 
		$a_01_1 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //00 00 
	condition:
		any of ($a_*)
 
}