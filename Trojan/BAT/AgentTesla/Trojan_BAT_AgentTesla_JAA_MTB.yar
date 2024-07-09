
rule Trojan_BAT_AgentTesla_JAA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.JAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 "
		
	strings :
		$a_02_0 = {0a 13 06 06 11 06 28 ?? ?? ?? 0a 11 05 da 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 0a 07 17 d6 0b 07 08 6f ?? ?? ?? 0a fe 04 13 07 11 07 2d c9 } //10
		$a_81_1 = {47 65 74 4d 65 74 68 6f 64 } //1 GetMethod
		$a_81_2 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_81_3 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
	condition:
		((#a_02_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=13
 
}