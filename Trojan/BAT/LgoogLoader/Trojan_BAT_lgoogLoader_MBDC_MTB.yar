
rule Trojan_BAT_lgoogLoader_MBDC_MTB{
	meta:
		description = "Trojan:BAT/lgoogLoader.MBDC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {00 00 0a 0c 08 04 16 04 8e 69 6f ?? 00 00 0a 0d de 0b } //1
		$a_01_1 = {57 bf a2 3f 09 0a 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 36 00 00 00 25 00 00 00 a0 00 00 00 35 01 00 00 93 00 00 00 03 00 00 00 6e 00 00 00 16 00 00 00 94 01 00 00 01 00 00 00 01 00 00 00 30 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}