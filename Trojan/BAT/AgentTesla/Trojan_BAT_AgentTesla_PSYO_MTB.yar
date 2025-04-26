
rule Trojan_BAT_AgentTesla_PSYO_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSYO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {16 0b 28 56 00 00 06 28 8d 00 00 0a 17 8d 5c 00 00 01 25 16 1f 5c 9d 6f 8e 00 00 0a 28 04 00 00 2b 0c 1a 13 08 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}