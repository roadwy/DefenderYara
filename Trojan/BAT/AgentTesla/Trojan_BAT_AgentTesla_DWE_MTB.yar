
rule Trojan_BAT_AgentTesla_DWE_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.DWE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {02 6c 23 ff b9 f4 ee 2a 81 f7 3f 5b 28 ?? ?? ?? 0a b7 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 0b 07 0a } //1
		$a_81_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_2 = {47 65 74 54 79 70 65 } //1 GetType
	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}