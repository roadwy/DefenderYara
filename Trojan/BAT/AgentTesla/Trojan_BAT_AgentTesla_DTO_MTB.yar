
rule Trojan_BAT_AgentTesla_DTO_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.DTO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {08 11 04 02 11 04 91 07 61 06 74 90 01 03 1b 09 91 61 20 9e 03 00 00 20 f0 03 00 00 90 00 } //1
		$a_03_1 = {02 08 18 20 96 00 00 00 20 a4 00 00 00 28 90 01 03 2b 1f 10 1f 3a 1f 26 28 90 01 03 2b 84 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}