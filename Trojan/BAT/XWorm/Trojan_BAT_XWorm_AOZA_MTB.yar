
rule Trojan_BAT_XWorm_AOZA_MTB{
	meta:
		description = "Trojan:BAT/XWorm.AOZA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 03 00 00 "
		
	strings :
		$a_03_0 = {05 0e 04 0e 06 0e 08 17 1f 40 28 ?? 00 00 06 0a 06 0e 05 0e 07 20 00 02 00 00 23 66 66 66 66 66 66 e6 3f 28 ?? 00 00 06 0b } //5
		$a_03_1 = {02 03 04 06 07 17 28 ?? 00 00 06 06 07 0e 06 0e 08 1f 0f 17 28 } //2
		$a_03_2 = {06 05 0e 04 23 00 00 00 00 a3 e1 b1 41 17 28 ?? 00 00 06 0b 02 03 04 06 07 05 0e 04 0e 05 23 33 33 33 33 33 33 d3 3f 28 } //2
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*2+(#a_03_2  & 1)*2) >=9
 
}