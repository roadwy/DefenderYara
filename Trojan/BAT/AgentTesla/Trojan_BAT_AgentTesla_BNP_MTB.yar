
rule Trojan_BAT_AgentTesla_BNP_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.BNP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_02_0 = {02 09 18 28 ?? ?? ?? 06 1f 10 28 ?? ?? ?? 06 84 28 ?? ?? ?? 06 28 ?? ?? ?? 06 26 } //1
		$a_02_1 = {09 02 8e 69 18 da 17 d6 17 da 17 d6 8d ?? ?? ?? 01 28 ?? ?? ?? 06 74 ?? ?? ?? 1b 0a } //1
		$a_81_2 = {47 65 74 54 79 70 65 } //1 GetType
		$a_81_3 = {47 65 74 50 69 78 65 6c } //1 GetPixel
		$a_81_4 = {65 6b 6f 76 6e 49 } //1 ekovnI
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}