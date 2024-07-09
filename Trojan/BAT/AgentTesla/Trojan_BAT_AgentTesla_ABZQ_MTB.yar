
rule Trojan_BAT_AgentTesla_ABZQ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABZQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {16 0c 2b 5b 16 0d 2b 4e 11 05 09 08 6f ?? 00 00 0a 13 0c 16 13 04 07 } //2
		$a_03_1 = {2b 1f 12 0c 28 ?? 00 00 0a 13 04 2b 14 12 0c 28 ?? 00 00 0a 13 04 2b 09 12 0c 28 ?? 00 00 0a 13 04 11 06 11 04 6f ?? 00 00 0a 09 17 58 0d 09 11 07 32 ad } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}