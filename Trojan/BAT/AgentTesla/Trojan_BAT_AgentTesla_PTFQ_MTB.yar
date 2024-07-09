
rule Trojan_BAT_AgentTesla_PTFQ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PTFQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {6f 49 00 00 0a dc 06 28 ?? 00 00 2b 28 ?? 00 00 2b 0a de 03 26 de bb } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}