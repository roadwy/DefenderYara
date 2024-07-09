
rule Trojan_BAT_AgentTesla_PSXJ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSXJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {6f 22 00 00 0a 0c 08 6f 23 00 00 0a 28 ?? 00 00 0a 73 25 00 00 0a 0d 09 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}