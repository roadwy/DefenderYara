
rule Trojan_BAT_AgentTesla_KNY_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.KNY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {58 20 00 01 00 00 5d 94 13 08 11 07 06 02 06 91 11 08 61 d2 9c 06 17 58 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_BAT_AgentTesla_KNY_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.KNY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {58 4a 17 6f 1f 01 00 0a 6f 20 01 00 0a 26 06 1e 58 06 1e 58 4a 17 d6 54 06 1e 58 4a 1f 46 31 cc 11 04 6f 21 01 00 0a } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}