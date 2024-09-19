
rule Trojan_BAT_AgentTesla_MBXE_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBXE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {16 13 0b 11 0c 06 91 11 18 61 13 19 11 0c 06 17 58 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}