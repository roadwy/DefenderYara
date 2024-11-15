
rule TrojanDropper_BAT_AgentTesla_AAT_MTB{
	meta:
		description = "TrojanDropper:BAT/AgentTesla.AAT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 04 11 07 02 17 8d 03 00 00 01 13 0a 11 0a 16 11 07 8c 16 00 00 01 a2 11 0a 14 28 ?? 00 00 0a 28 ?? 00 00 0a 09 b4 28 ?? 00 00 06 28 ?? 00 00 0a 9c 11 07 17 d6 13 07 11 07 11 0b 3e 48 ff ff ff } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}