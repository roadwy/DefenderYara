
rule Trojan_BAT_AgentTesla_PSAQ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSAQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {09 12 05 28 1a 00 00 0a 18 2c 11 08 06 18 6f 1b 00 00 0a 11 04 28 1c 00 00 0a 13 06 07 06 11 06 6f 1d 00 00 0a de 0b } //5
		$a_01_1 = {08 6f 1f 00 00 0a 32 ae 07 6f 20 00 00 0a 28 01 00 00 2b 2a 28 09 00 00 06 38 63 ff ff ff 73 22 00 00 0a } //5
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}