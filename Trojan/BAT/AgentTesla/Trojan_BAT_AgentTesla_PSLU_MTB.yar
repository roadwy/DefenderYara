
rule Trojan_BAT_AgentTesla_PSLU_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSLU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {28 2a 00 00 0a 7e 01 00 00 04 02 08 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a a5 01 00 00 1b 0b 11 07 20 42 2c b6 fe 5a 20 f8 98 51 58 61 38 63 fd ff ff d0 01 00 00 1b 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 11 05 28 2e 00 00 0a 13 06 7e 01 00 00 04 02 11 06 16 11 04 1a 59 28 29 00 00 0a 11 07 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}