
rule Trojan_BAT_FormBook_ARAC_MTB{
	meta:
		description = "Trojan:BAT/FormBook.ARAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 11 05 06 8e 69 5d 06 11 05 06 8e 69 5d 91 07 11 05 1f 16 5d 91 61 28 ?? ?? ?? 0a 06 11 05 17 58 06 8e 69 5d 91 28 ?? ?? ?? 0a 59 20 00 01 00 00 58 20 00 01 00 00 5d d2 9c 00 11 05 15 58 13 05 11 05 16 fe 04 16 fe 01 13 06 11 06 2d b0 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}