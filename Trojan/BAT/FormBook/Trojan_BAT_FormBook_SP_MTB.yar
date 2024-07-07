
rule Trojan_BAT_FormBook_SP_MTB{
	meta:
		description = "Trojan:BAT/FormBook.SP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {08 04 03 8e 69 28 90 01 03 06 d6 0d 09 04 5f 13 04 08 03 8e 69 28 90 01 03 06 13 05 03 11 05 91 13 06 11 06 11 04 28 90 01 03 06 28 90 01 03 0a 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}