
rule Trojan_BAT_XWorm_NMD_MTB{
	meta:
		description = "Trojan:BAT/XWorm.NMD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {02 06 02 06 91 03 61 0b 12 01 28 ?? 00 00 0a 28 ?? 00 00 0a 9c 06 17 58 0a 06 02 8e 69 32 e1 } //4
		$a_01_1 = {0b 07 28 07 00 00 0a 07 28 08 00 00 0a 0c 08 6f 09 00 00 0a 14 14 6f 0a 00 00 0a 26 16 0d 09 1f 63 33 28 7e 0b 00 00 0a 72 27 00 00 70 17 6f 0c 00 00 0a 13 04 11 04 72 83 00 00 70 28 0d 00 00 0a 6f 0e 00 00 0a 6f 0f 00 00 0a } //2
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*2) >=6
 
}