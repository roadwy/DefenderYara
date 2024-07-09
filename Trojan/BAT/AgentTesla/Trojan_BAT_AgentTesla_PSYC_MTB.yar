
rule Trojan_BAT_AgentTesla_PSYC_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSYC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {38 5f ff ff ff 28 ?? 00 00 0a 7e 01 00 00 04 02 08 6f 31 00 00 0a 28 ?? 00 00 0a a5 01 00 00 1b 0b 11 07 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}