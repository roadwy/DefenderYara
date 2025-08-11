
rule Trojan_BAT_FormBook_AGB_MTB{
	meta:
		description = "Trojan:BAT/FormBook.AGB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 0b 11 08 18 6a 58 20 00 01 00 00 6a 5d d4 91 61 d2 13 1c 11 1a 11 0b 11 08 20 00 01 00 00 6a 5d d4 91 61 d2 13 1d 11 1b 11 0b 11 08 17 6a 58 20 00 01 00 00 6a 5d d4 91 61 d2 13 1e } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}