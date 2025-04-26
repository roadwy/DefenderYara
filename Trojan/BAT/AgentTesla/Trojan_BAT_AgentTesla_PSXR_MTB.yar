
rule Trojan_BAT_AgentTesla_PSXR_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSXR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {7b d1 00 00 04 6f ?? 00 00 0a 6f ?? 02 00 06 00 0b 07 28 ?? 02 00 06 0c 73 a0 00 00 06 0d 09 73 59 00 00 06 13 04 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}