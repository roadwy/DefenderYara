
rule Trojan_BAT_AgentTesla_ASAI_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ASAI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {2d 16 2b 1c 12 13 28 ?? 00 00 0a 0d 2b 12 12 13 28 ?? 00 00 0a 0d 2b 08 12 13 28 ?? 00 00 0a 0d 11 06 09 6f ?? 00 00 0a 08 17 58 0c 08 11 08 fe 04 13 0e 11 0e 3a } //4
		$a_03_1 = {11 04 08 07 6f ?? 00 00 0a 13 13 16 0d 11 0a 06 9a 13 0d 11 0d 13 05 11 05 } //1
	condition:
		((#a_03_0  & 1)*4+(#a_03_1  & 1)*1) >=5
 
}