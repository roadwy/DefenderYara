
rule Trojan_BAT_FormBook_RYM_MTB{
	meta:
		description = "Trojan:BAT/FormBook.RYM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 07 03 6f 90 01 03 0a 5d 17 58 28 90 01 03 0a 28 90 01 03 0a 59 0d 06 09 28 90 01 03 0a 28 90 01 03 0a 28 90 01 03 0a 0a 07 17 58 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}