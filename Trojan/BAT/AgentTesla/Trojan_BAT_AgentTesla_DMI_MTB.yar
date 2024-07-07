
rule Trojan_BAT_AgentTesla_DMI_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.DMI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {02 08 18 28 90 01 03 06 1f 10 28 90 01 03 06 84 28 90 01 03 06 28 90 01 03 06 26 00 08 18 d6 0c 90 00 } //1
		$a_03_1 = {02 11 04 91 07 61 06 09 91 61 28 90 01 03 06 9c 09 90 00 } //1
		$a_01_2 = {00 53 65 6c 65 63 74 6f 72 58 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}