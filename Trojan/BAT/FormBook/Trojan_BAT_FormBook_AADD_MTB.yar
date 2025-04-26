
rule Trojan_BAT_FormBook_AADD_MTB{
	meta:
		description = "Trojan:BAT/FormBook.AADD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 13 08 2b 35 00 11 05 11 08 08 11 08 91 11 04 61 09 11 06 91 61 28 ?? 00 00 0a 9c 11 06 1f 15 fe 01 13 09 11 09 2c 05 16 13 06 2b 06 11 06 17 58 13 06 00 11 08 17 58 13 08 11 08 08 8e 69 17 59 fe 02 16 fe 01 13 0a 11 0a 2d b9 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}