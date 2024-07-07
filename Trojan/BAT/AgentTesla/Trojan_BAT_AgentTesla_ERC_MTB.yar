
rule Trojan_BAT_AgentTesla_ERC_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ERC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {11 03 11 06 02 11 06 91 11 02 18 d6 18 da 61 11 01 11 07 19 d6 19 da 91 61 b4 9c } //1
		$a_03_1 = {11 01 02 11 03 18 6f 90 01 03 0a 1f 10 28 90 01 03 0a 28 90 01 03 06 6f 90 01 03 0a 26 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}