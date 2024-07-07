
rule Trojan_BAT_StealC_NB_MTB{
	meta:
		description = "Trojan:BAT/StealC.NB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {59 93 61 11 0b 90 01 01 2c 00 00 1b 11 09 11 0c 58 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}
rule Trojan_BAT_StealC_NB_MTB_2{
	meta:
		description = "Trojan:BAT/StealC.NB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {7e 0e 00 00 04 16 fe 06 90 01 01 00 00 06 9b 16 2d e5 7e 90 01 01 00 00 04 17 fe 06 90 01 01 00 00 06 9b 16 2d e0 90 00 } //3
		$a_03_1 = {8d 37 00 00 01 80 90 01 01 00 00 04 7e 90 01 01 00 00 04 16 fe 06 90 01 01 00 00 06 9b 7e 0b 00 00 04 17 fe 06 90 01 01 00 00 06 9b 7e 90 01 01 00 00 04 18 fe 06 90 01 01 00 00 06 9b 90 00 } //3
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*3) >=6
 
}