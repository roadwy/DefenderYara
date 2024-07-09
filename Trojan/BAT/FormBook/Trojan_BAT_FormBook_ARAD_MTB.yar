
rule Trojan_BAT_FormBook_ARAD_MTB{
	meta:
		description = "Trojan:BAT/FormBook.ARAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {07 11 05 07 8e 69 5d 02 11 05 08 07 28 ?? ?? ?? 06 9c 00 11 05 15 58 13 05 11 05 16 fe 04 16 fe 01 13 06 11 06 2d d8 } //5
		$a_03_1 = {05 03 05 8e 69 5d 91 04 03 1f 16 5d 91 61 28 ?? ?? ?? 0a 05 03 17 58 05 8e 69 5d 91 28 ?? ?? ?? 0a 59 20 00 01 00 00 58 20 00 01 00 00 5d d2 0a 2b 00 06 2a } //5
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}