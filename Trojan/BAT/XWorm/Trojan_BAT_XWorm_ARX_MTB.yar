
rule Trojan_BAT_XWorm_ARX_MTB{
	meta:
		description = "Trojan:BAT/XWorm.ARX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {0b 16 0c 2b 3a 06 08 9a 28 ?? 00 00 0a 03 08 03 6f ?? 00 00 0a 5d 6f ?? 00 00 0a 0d 09 59 08 1f 2b 5d 59 20 00 01 00 00 58 20 00 01 00 00 5d d1 13 04 07 11 04 6f ?? 00 00 0a 26 08 17 58 0c } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}
rule Trojan_BAT_XWorm_ARX_MTB_2{
	meta:
		description = "Trojan:BAT/XWorm.ARX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {0a 16 0b 2b 1b 06 07 18 58 5a 06 07 17 58 1f 1f 5f 63 61 0a 06 20 87 d6 12 00 5d 0a 07 17 58 0b 07 1d } //3
		$a_03_1 = {11 05 11 06 9a 0b 07 6f ?? 00 00 0a 6f ?? 00 00 0a 0c 08 72 31 00 00 70 6f ?? 00 00 0a 3a 92 00 00 00 08 72 3f 00 00 70 6f } //2
	condition:
		((#a_01_0  & 1)*3+(#a_03_1  & 1)*2) >=5
 
}