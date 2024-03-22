
rule Trojan_BAT_FormBook_FDAA_MTB{
	meta:
		description = "Trojan:BAT/FormBook.FDAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {11 01 11 0a 11 10 11 13 5d d2 9c } //01 00 
		$a_01_1 = {11 0c 11 0d 61 13 0f } //01 00 
		$a_01_2 = {11 01 11 0b 91 11 13 58 13 0e } //01 00 
		$a_01_3 = {11 07 1f 16 5d 91 13 0d } //00 00 
	condition:
		any of ($a_*)
 
}