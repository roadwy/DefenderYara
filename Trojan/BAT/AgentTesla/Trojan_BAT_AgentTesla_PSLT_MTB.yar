
rule Trojan_BAT_AgentTesla_PSLT_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSLT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {20 00 10 00 00 8d 59 00 00 01 0d 73 ?? ?? ?? 0a 13 04 08 09 16 20 00 10 00 00 6f ?? ?? ?? 0a 13 05 11 05 16 31 0b 11 04 09 16 11 05 6f ?? ?? ?? 0a 11 05 16 30 dc 28 ?? ?? ?? 0a 11 04 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 28 28 00 00 06 de 16 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}