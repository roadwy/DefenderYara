
rule Trojan_BAT_AgentTesla_CAJ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CAJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 0a 2b 5c 00 72 01 00 00 70 28 ?? 00 00 06 73 ?? 00 00 0a 0b 73 ?? 00 00 0a 0c 07 16 73 ?? 00 00 0a 73 ?? 00 00 0a 0d 09 08 6f ?? 00 00 0a de 0a } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}