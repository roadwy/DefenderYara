
rule Trojan_BAT_AgentTesla_DNC_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.DNC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {06 02 08 18 6f 90 01 03 0a 1f 10 28 90 01 03 0a 84 90 00 } //1
		$a_03_1 = {08 11 04 02 11 04 91 07 61 06 09 91 61 28 90 01 03 0a 9c 09 15 90 00 } //1
		$a_01_2 = {00 53 65 6c 65 63 74 6f 72 58 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}