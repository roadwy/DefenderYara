
rule Trojan_BAT_AgentTesla_ERS_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ERS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {09 11 06 02 11 06 91 08 18 d6 18 da 61 07 11 07 19 d6 19 da 91 61 b4 9c } //1
		$a_01_1 = {02 02 8e 69 17 da 91 1f 70 61 0c 02 8e 69 17 d6 17 da } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}