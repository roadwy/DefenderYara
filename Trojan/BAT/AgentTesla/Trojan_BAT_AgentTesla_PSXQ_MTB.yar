
rule Trojan_BAT_AgentTesla_PSXQ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSXQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 0c 02 28 90 01 01 00 00 06 75 01 00 00 1b 73 06 00 00 0a 0d 09 07 16 73 07 00 00 0a 13 04 11 04 08 6f 08 00 00 0a 08 13 05 dd 29 00 00 00 11 04 39 07 00 00 00 11 04 6f 09 00 00 0a dc 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}