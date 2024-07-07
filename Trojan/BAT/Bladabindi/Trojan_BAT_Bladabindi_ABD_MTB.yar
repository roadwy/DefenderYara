
rule Trojan_BAT_Bladabindi_ABD_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.ABD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {20 00 0c 00 00 28 90 01 03 0a 06 03 6f 90 01 03 0a 0b 07 8e 69 16 31 04 07 0c de 0e 14 0c de 0a 06 2c 06 06 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_Bladabindi_ABD_MTB_2{
	meta:
		description = "Trojan:BAT/Bladabindi.ABD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {7e 0d 00 00 04 a2 11 12 18 28 90 01 03 0a 13 0f 12 0f 28 90 01 03 06 a2 11 12 19 7e 0d 00 00 04 a2 11 12 1a 7e 0e 00 00 04 13 10 12 10 28 90 01 03 06 a2 11 12 1b 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}