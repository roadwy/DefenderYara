
rule Trojan_BAT_AgentTesla_MBHY_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBHY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {4c 00 6f 00 61 00 64 00 00 11 47 00 65 00 74 00 54 00 79 00 70 00 65 00 73 00 00 13 47 00 65 00 74 00 4d 00 65 00 74 00 68 00 6f 00 64 00 00 11 44 00 65 00 6c 00 65 00 74 00 65 00 4d 00 43 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}