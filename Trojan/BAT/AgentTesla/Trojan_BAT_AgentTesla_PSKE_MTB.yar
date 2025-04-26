
rule Trojan_BAT_AgentTesla_PSKE_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSKE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {16 0c 2b 17 03 07 08 6f 29 00 00 0a 0d 06 07 12 03 28 2a 00 00 0a 9c 08 17 58 0c 08 03 6f 2b 00 00 0a 32 e0 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}