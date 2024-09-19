
rule Trojan_BAT_FormBook_OKZ_MTB{
	meta:
		description = "Trojan:BAT/FormBook.OKZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {7e 22 03 00 04 02 28 1f 07 00 06 13 05 7e 2d 03 00 04 11 04 11 05 16 11 05 8e 69 28 3a 07 00 06 13 06 7e 2e 03 00 04 7e ab 02 00 04 28 f3 06 00 06 11 06 28 3d 07 00 06 13 07 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}