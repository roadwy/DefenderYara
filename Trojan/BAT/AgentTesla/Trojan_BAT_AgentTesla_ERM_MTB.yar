
rule Trojan_BAT_AgentTesla_ERM_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ERM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {07 02 09 28 90 01 03 06 1f 10 28 90 01 03 0a 28 90 01 03 0a 6f 90 01 03 0a 26 09 18 d6 0d 90 00 } //1
		$a_01_1 = {09 11 06 02 11 06 91 08 18 d6 18 da 61 07 11 07 19 d6 19 da 91 61 b4 9c } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}