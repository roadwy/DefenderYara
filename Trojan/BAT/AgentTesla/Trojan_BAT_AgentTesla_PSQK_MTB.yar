
rule Trojan_BAT_AgentTesla_PSQK_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSQK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {28 27 00 00 0a 7e 01 00 00 04 02 08 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a a5 01 00 00 1b 0b 11 07 20 07 41 65 e7 5a 20 15 a1 3c 4e 61 38 9a fe ff ff 02 20 ff ff ff 3f 5f 10 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}