
rule Trojan_BAT_AgentTesla_CRN_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CRN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_03_0 = {07 06 09 18 5a 18 28 ?? ?? ?? 06 1f 10 28 ?? ?? ?? 06 d2 } //1
		$a_01_1 = {53 75 62 73 74 72 69 6e 67 } //1 Substring
		$a_01_2 = {54 6f 55 49 6e 74 33 32 } //1 ToUInt32
		$a_01_3 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_01_4 = {47 65 74 54 79 70 65 46 72 6f 6d 48 61 6e 64 6c 65 } //1 GetTypeFromHandle
		$a_01_5 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggableAttribute
		$a_01_6 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //1 DebuggingModes
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}