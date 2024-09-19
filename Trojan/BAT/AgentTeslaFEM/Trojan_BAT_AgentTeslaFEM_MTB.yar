
rule Trojan_BAT_AgentTeslaFEM_MTB{
	meta:
		description = "Trojan:BAT/AgentTeslaFEM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 05 11 06 6f 33 00 00 0a 13 07 08 12 07 28 34 00 00 0a 6f 35 00 00 0a 00 08 12 07 28 36 00 00 0a 6f 35 00 00 0a 00 08 12 07 28 37 00 00 0a 6f 35 00 00 0a 00 07 08 20 00 1c 01 00 28 0f 00 00 06 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}