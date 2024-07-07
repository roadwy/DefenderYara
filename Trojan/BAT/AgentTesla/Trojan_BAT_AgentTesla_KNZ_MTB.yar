
rule Trojan_BAT_AgentTesla_KNZ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.KNZ!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {19 8d 01 00 00 01 25 16 72 01 00 00 70 a2 25 17 72 23 00 00 70 a2 25 18 72 7d 00 00 70 a2 18 9a 2b 11 2b 16 2b 1b 14 2b 1f 2b 24 2a 28 35 00 00 0a 2b cd 6f 0f 00 00 0a 2b e8 28 88 0c 00 06 2b e3 28 36 00 00 0a 2b de 28 81 0c 00 06 2b da 6f 37 00 00 0a 2b d5 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}