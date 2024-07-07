
rule Trojan_BAT_AgentTesla_DJD_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.DJD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 02 11 08 02 11 08 91 11 01 61 11 00 11 03 91 61 28 90 01 03 06 9c 90 00 } //1
		$a_03_1 = {11 05 02 11 02 18 6f 90 01 03 0a 1f 10 28 90 01 03 0a 84 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}