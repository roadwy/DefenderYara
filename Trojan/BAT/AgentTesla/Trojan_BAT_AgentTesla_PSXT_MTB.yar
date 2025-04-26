
rule Trojan_BAT_AgentTesla_PSXT_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSXT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 72 2b 00 00 70 28 ?? 00 00 0a 72 5d 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 0b 73 12 00 00 0a 0c 02 28 ?? 00 00 06 75 01 00 00 1b } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}