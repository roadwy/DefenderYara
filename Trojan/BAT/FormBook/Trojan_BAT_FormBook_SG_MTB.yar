
rule Trojan_BAT_FormBook_SG_MTB{
	meta:
		description = "Trojan:BAT/FormBook.SG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {7e 51 00 00 04 7e 52 00 00 04 06 28 f8 00 00 06 0b } //00 00 
	condition:
		any of ($a_*)
 
}