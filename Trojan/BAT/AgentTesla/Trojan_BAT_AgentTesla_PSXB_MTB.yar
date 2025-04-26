
rule Trojan_BAT_AgentTesla_PSXB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSXB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {28 bd 01 00 0a 08 6f ?? 00 00 0a 6f ?? 01 00 0a 20 3e ed c0 07 28 ?? 01 00 06 6f ?? 01 00 0a 13 09 11 07 6f ?? 01 00 0a 16 31 1a } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}