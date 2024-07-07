
rule Trojan_BAT_AgentTesla_AKT_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AKT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_03_0 = {01 0a 06 16 28 90 01 03 06 a2 06 17 28 90 01 03 06 a2 06 18 72 90 01 03 70 a2 28 90 01 03 06 0b 07 28 90 01 03 06 0c 08 90 00 } //10
		$a_03_1 = {11 05 09 11 0b 18 5a 18 6f 90 01 03 0a 1f 10 28 90 01 03 0a d2 8c 90 01 03 01 6f 90 01 03 0a 26 00 11 0b 17 58 13 0b 11 0b 11 04 fe 04 13 0c 11 0c 2d cc 90 00 } //10
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10) >=20
 
}