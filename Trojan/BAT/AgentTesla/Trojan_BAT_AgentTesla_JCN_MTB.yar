
rule Trojan_BAT_AgentTesla_JCN_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.JCN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 07 00 00 "
		
	strings :
		$a_02_0 = {0a 0a 02 06 6f ?? ?? ?? 0a d4 8d ?? ?? ?? 01 7d ?? ?? ?? 04 06 02 7b ?? ?? ?? 04 16 02 7b ?? ?? ?? 04 8e 69 6f ?? ?? ?? 0a 26 02 } //10
		$a_81_1 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //1 DebuggingModes
		$a_81_2 = {43 6c 61 73 73 4c 69 62 72 61 72 79 } //1 ClassLibrary
		$a_81_3 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_81_4 = {52 65 70 6c 61 63 65 } //1 Replace
		$a_81_5 = {47 65 74 53 74 72 69 6e 67 } //1 GetString
		$a_81_6 = {47 65 74 45 78 65 63 75 74 69 6e 67 41 73 73 65 6d 62 6c 79 } //1 GetExecutingAssembly
	condition:
		((#a_02_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=16
 
}