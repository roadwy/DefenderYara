
rule Trojan_BAT_AgentTesla_CEL1_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CEL1!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_02_0 = {16 09 8e 69 6f ?? ?? ?? 0a 26 28 ?? ?? ?? 0a 09 6f ?? ?? ?? 0a 20 ?? ?? ?? ?? 28 ?? ?? ?? 06 7e ?? ?? ?? 0a 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 0a de 0a 90 09 0f 00 08 6f ?? ?? ?? 0a d4 8d ?? ?? ?? 01 0d 08 09 } //1
		$a_81_1 = {47 65 74 4d 61 6e 69 66 65 73 74 52 65 73 6f 75 72 63 65 53 74 72 65 61 6d } //1 GetManifestResourceStream
		$a_81_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_81_3 = {47 65 74 45 78 65 63 75 74 69 6e 67 41 73 73 65 6d 62 6c 79 } //1 GetExecutingAssembly
		$a_81_4 = {47 65 74 53 74 72 69 6e 67 } //1 GetString
	condition:
		((#a_02_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}