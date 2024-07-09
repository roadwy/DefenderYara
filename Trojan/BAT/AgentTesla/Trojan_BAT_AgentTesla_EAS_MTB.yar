
rule Trojan_BAT_AgentTesla_EAS_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EAS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 0b 06 72 ?? 02 00 70 6f ?? 00 00 0a 74 02 00 00 1b 0c 08 28 ?? 00 00 0a 00 07 08 6f ?? 00 00 0a 00 07 06 72 ?? 02 00 70 6f ?? 00 00 0a 74 02 00 00 1b 6f ?? 00 00 0a 00 07 06 72 ?? 02 00 70 6f ?? 00 00 0a 74 02 00 00 1b 6f ?? 00 00 0a 00 02 28 ?? 00 00 0a 00 28 ?? 00 00 0a 07 6f ?? 00 00 0a 6f ?? 00 00 0a 0d 09 6f ?? 00 00 0a 17 9a 7e ?? 00 00 04 13 04 11 04 28 } //3
		$a_01_1 = {4e 00 75 00 64 00 65 00 5f 00 50 00 68 00 6f 00 74 00 6f 00 73 00 } //2 Nude_Photos
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}