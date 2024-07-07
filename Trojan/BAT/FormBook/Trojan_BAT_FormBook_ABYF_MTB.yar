
rule Trojan_BAT_FormBook_ABYF_MTB{
	meta:
		description = "Trojan:BAT/FormBook.ABYF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 0a 2b 29 06 08 5d 13 09 06 08 5b 13 0a 07 11 09 11 0a 6f 90 01 01 00 00 0a 13 0d 11 04 09 12 0d 28 90 01 01 00 00 0a 9c 09 17 58 0d 06 17 58 0a 06 08 11 06 5a fe 04 13 0b 11 0b 2d ca 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}