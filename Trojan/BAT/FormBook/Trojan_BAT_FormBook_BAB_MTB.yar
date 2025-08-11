
rule Trojan_BAT_FormBook_BAB_MTB{
	meta:
		description = "Trojan:BAT/FormBook.BAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 07 11 07 07 11 07 94 03 5a 1f 64 5d 9e 00 11 07 17 58 13 07 11 07 07 8e 69 fe 04 13 08 11 08 2d de } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}