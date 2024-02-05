
rule Trojan_BAT_FormBook_MFP_MTB{
	meta:
		description = "Trojan:BAT/FormBook.MFP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {02 11 04 91 07 61 06 } //01 00 
		$a_01_1 = {08 11 04 11 05 d2 9c 09 03 } //00 00 
	condition:
		any of ($a_*)
 
}