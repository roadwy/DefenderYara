
rule Trojan_BAT_XWorm_AYZA_MTB{
	meta:
		description = "Trojan:BAT/XWorm.AYZA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {05 0e 04 0e 06 0e 08 17 1f 30 28 ?? 00 00 06 0a 06 0e 05 0e 07 20 00 01 00 00 23 00 00 00 00 00 00 e8 3f 28 ?? 00 00 06 0b } //4
		$a_03_1 = {02 03 04 06 07 17 28 ?? 00 00 06 06 07 0e 06 0e 08 1f 12 17 28 ?? 00 00 06 2a } //2
	condition:
		((#a_03_0  & 1)*4+(#a_03_1  & 1)*2) >=6
 
}