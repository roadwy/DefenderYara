
rule Trojan_BAT_AgentTesla_CZJ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CZJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {06 11 04 28 ?? ?? ?? 0a 07 da 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 0a } //1
		$a_01_1 = {53 74 72 52 65 76 65 72 73 65 } //1 StrReverse
		$a_01_2 = {68 00 78 00 2e 00 6a 00 39 00 } //1 hx.j9
		$a_01_3 = {47 65 74 54 79 70 65 } //1 GetType
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}