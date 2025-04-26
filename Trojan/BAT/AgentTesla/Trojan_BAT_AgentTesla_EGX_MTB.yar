
rule Trojan_BAT_AgentTesla_EGX_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EGX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {13 04 11 04 28 ?? ?? ?? 0a 20 9e 02 00 00 da 13 05 11 05 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 13 06 07 11 06 28 ?? ?? ?? 0a 0b 00 09 17 d6 0d 90 09 0c 00 08 09 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a } //1
		$a_01_1 = {67 00 6e 00 69 00 72 00 74 00 53 00 34 00 36 00 65 00 73 00 61 00 42 00 6d 00 6f 00 72 00 46 00 } //1 gnirtS46esaBmorF
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}