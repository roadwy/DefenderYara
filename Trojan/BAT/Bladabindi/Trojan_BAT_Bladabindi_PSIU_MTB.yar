
rule Trojan_BAT_Bladabindi_PSIU_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.PSIU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 20 98 3a 00 00 28 90 01 03 0a 00 28 0c 00 00 06 0a 20 98 3a 00 00 28 90 01 03 0a 00 06 72 33 00 00 70 72 67 00 00 70 6f 90 01 03 0a 28 90 01 03 0a 0b 20 98 3a 00 00 28 33 00 00 0a 00 02 07 28 14 00 00 06 00 2a 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}