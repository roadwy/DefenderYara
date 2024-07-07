
rule Trojan_BAT_AgentTesla_PSYW_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSYW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 08 8d 05 00 00 01 0d 11 09 09 16 09 8e 69 28 90 01 01 00 00 0a 11 07 09 16 09 8e 69 6f 7c 00 00 0a de 0c 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}