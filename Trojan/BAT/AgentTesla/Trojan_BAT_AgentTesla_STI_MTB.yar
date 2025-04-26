
rule Trojan_BAT_AgentTesla_STI_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.STI!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {72 01 00 00 70 28 0c 00 00 0a 73 0d 00 00 0a 0a 06 72 27 00 00 70 6f 0e 00 00 0a 28 0f 00 00 0a 28 04 00 00 06 0b 06 72 4d 00 00 70 6f 0e 00 00 0a 28 0f 00 00 0a 28 04 00 00 06 0c 16 08 8e 69 20 00 10 00 00 1f 40 28 02 00 00 06 0d 16 07 8e 69 20 00 10 00 00 1f 40 28 02 00 00 06 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}