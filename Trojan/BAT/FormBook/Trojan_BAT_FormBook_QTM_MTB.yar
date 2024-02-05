
rule Trojan_BAT_FormBook_QTM_MTB{
	meta:
		description = "Trojan:BAT/FormBook.QTM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8d 16 00 00 01 0d 16 13 04 2b 22 09 11 04 08 11 04 08 8e 69 5d 91 06 11 04 91 61 d2 9c 2b 03 } //00 00 
	condition:
		any of ($a_*)
 
}