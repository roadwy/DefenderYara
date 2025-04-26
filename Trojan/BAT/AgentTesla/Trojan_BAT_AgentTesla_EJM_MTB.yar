
rule Trojan_BAT_AgentTesla_EJM_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EJM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {13 04 11 04 28 ?? ?? ?? 06 20 9e 02 00 00 da 13 05 11 05 28 ?? ?? ?? 06 28 ?? ?? ?? 06 13 06 07 11 06 28 ?? ?? ?? 06 0b 00 09 17 d6 0d 90 09 0c 00 08 09 28 ?? ?? ?? 06 28 ?? ?? ?? 06 } //1
		$a_01_1 = {00 54 6f 43 68 61 72 41 72 72 61 79 00 } //1
		$a_01_2 = {00 46 72 6f 6d 42 61 73 65 36 34 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}