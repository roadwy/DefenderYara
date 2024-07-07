
rule Trojan_BAT_AgentTesla_MZL_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MZL!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {38 90 02 00 00 38 95 02 00 00 38 96 02 00 00 28 d5 00 00 0a 0d 72 2f 00 00 70 17 8d 81 00 00 01 25 16 1f 2c 9d 28 d6 00 00 0a 13 04 7e d7 00 00 0a 13 05 16 13 06 16 13 07 06 16 54 2b 1e } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}