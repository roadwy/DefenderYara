
rule Trojan_BAT_AgentTesla_BAJ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.BAJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {25 16 1f 2d 9d 6f ?? 00 00 0a 0a 06 8e 69 8d ?? 00 00 01 0b 16 13 05 2b 16 07 11 05 06 11 05 9a 1f 10 28 ?? 00 00 0a d2 9c 11 05 17 58 13 05 11 05 06 8e 69 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}