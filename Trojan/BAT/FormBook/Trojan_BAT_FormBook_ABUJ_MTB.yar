
rule Trojan_BAT_FormBook_ABUJ_MTB{
	meta:
		description = "Trojan:BAT/FormBook.ABUJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 0d 2b 20 00 07 09 18 6f 90 01 01 00 00 0a 1f 10 28 90 01 01 00 00 0a 13 07 08 11 07 6f 90 01 01 00 00 0a 00 09 18 58 0d 00 09 07 6f 90 01 01 00 00 0a fe 04 13 08 11 08 2d d1 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}