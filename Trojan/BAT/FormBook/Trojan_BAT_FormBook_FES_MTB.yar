
rule Trojan_BAT_FormBook_FES_MTB{
	meta:
		description = "Trojan:BAT/FormBook.FES!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {25 47 03 06 03 8e 69 5d 91 61 d2 52 06 1b 2c e3 17 58 1e 2d 12 26 06 02 8e } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}