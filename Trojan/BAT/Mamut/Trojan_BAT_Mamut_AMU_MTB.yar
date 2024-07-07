
rule Trojan_BAT_Mamut_AMU_MTB{
	meta:
		description = "Trojan:BAT/Mamut.AMU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {16 0c 2b 34 16 0a 16 0d 2b 18 00 06 02 09 6f 80 00 00 0a 03 09 6f 80 00 00 0a 61 60 0a 00 09 17 58 0d 09 02 6f 15 00 00 0a fe 04 13 04 11 04 2d d9 } //1
		$a_01_1 = {0b 16 0c 2b 18 07 08 18 5b 02 08 18 6f 78 00 00 0a 1f 10 28 7f 00 00 0a 9c 08 18 58 0c 08 06 fe 04 0d 09 2d e0 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}