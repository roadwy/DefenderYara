
rule Trojan_BAT_AgentTesla_BZM_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.BZM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {07 02 09 18 28 90 01 03 06 1f 10 28 90 01 03 0a 84 28 90 01 03 0a 28 90 01 03 06 26 38 90 00 } //1
		$a_02_1 = {09 11 06 02 11 06 91 08 61 07 11 07 91 61 b4 9c 11 07 03 28 90 01 03 06 17 da 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}