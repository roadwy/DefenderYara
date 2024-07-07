
rule Trojan_BAT_FormBook_AAK_MTB{
	meta:
		description = "Trojan:BAT/FormBook.AAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 13 06 2b 3f 11 06 1d 5d 16 fe 01 13 07 11 07 2c 18 11 04 07 17 6f 90 01 03 0a 11 06 91 1d 61 b4 6f 90 01 03 0a 00 00 2b 14 00 11 04 07 17 6f 90 01 03 0a 11 06 91 6f 90 01 03 0a 00 00 11 06 17 d6 13 06 11 06 11 05 31 bb 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}