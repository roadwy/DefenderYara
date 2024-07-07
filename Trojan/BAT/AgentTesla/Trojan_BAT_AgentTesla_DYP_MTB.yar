
rule Trojan_BAT_AgentTesla_DYP_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.DYP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {08 11 04 02 11 04 91 07 61 06 75 90 01 03 1b 09 91 61 20 90 01 04 20 90 01 04 28 90 01 03 06 9c 90 00 } //1
		$a_03_1 = {01 02 08 18 90 01 04 28 90 01 03 2b 1f 10 20 90 01 04 20 90 01 04 28 90 01 03 2b 84 20 90 01 04 20 90 01 04 28 90 01 03 06 6f 90 01 03 0a 26 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}