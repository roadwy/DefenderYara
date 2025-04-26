
rule Trojan_BAT_AgentTesla_PSYT_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSYT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {20 2e 40 00 00 28 ?? 00 00 06 28 ?? 00 00 06 20 03 40 00 00 28 ?? 00 00 06 28 ?? 00 00 06 6f 03 00 00 0a 13 0b } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}