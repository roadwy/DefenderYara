
rule Trojan_BAT_AgentTesla_PSXV_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSXV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 05 6f 2a 00 00 0a 00 02 7b 16 00 00 04 08 6f 2b 00 00 0a 1f 64 6a 5a 08 6f 2c 00 00 0a 5b 69 18 8d 55 00 00 01 25 16 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}