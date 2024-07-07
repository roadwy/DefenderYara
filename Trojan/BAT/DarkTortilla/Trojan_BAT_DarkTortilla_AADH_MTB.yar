
rule Trojan_BAT_DarkTortilla_AADH_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.AADH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {06 1a 5d 16 fe 01 2c 56 02 17 8d 90 01 01 00 00 01 25 16 06 8c 90 01 01 00 00 01 a2 14 28 90 01 01 00 00 0a 28 90 01 01 00 00 0a 0c 02 18 8d 90 01 01 00 00 01 25 16 06 8c 90 01 01 00 00 01 a2 25 17 08 6a 90 00 } //2
		$a_03_1 = {0a b9 61 8c 90 01 01 00 00 01 a2 14 28 90 01 01 00 00 0a 06 17 d6 0a 06 07 fe 04 2d 98 90 00 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}