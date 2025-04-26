
rule Trojan_BAT_AgentTesla_PSOD_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSOD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {28 24 00 00 0a 7e 01 00 00 04 02 08 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a a5 01 00 00 1b 0b 11 07 20 fc 73 f5 3d 5a 20 be 2e 12 d7 61 38 6f ff ff ff 09 16 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}