
rule Trojan_BAT_AgentTesla_AKP_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AKP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_03_0 = {25 16 03 a2 25 0d 14 14 17 8d 90 01 03 01 25 16 17 9c 25 13 04 28 90 01 03 0a 11 04 16 91 2d 02 2b 0a 09 16 9a 28 90 01 03 0a 10 01 74 90 01 03 01 0b 07 90 00 } //10
		$a_03_1 = {25 16 08 a2 25 17 19 8d 90 01 03 01 25 16 28 90 01 03 06 a2 25 17 28 90 01 03 06 a2 25 18 72 90 01 03 70 a2 a2 25 0d 14 14 18 8d 90 01 03 01 25 16 17 9c 25 13 04 17 90 00 } //10
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10) >=20
 
}