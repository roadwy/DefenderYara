
rule Trojan_BAT_FormBook_ABSP_MTB{
	meta:
		description = "Trojan:BAT/FormBook.ABSP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {08 07 11 04 18 6f 90 01 01 00 00 0a 1f 10 28 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 00 00 11 04 18 58 13 04 11 04 07 6f 90 01 01 00 00 0a fe 04 13 05 11 05 2d d1 90 00 } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}