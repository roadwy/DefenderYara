
rule Trojan_BAT_AgentTesla_ADN_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ADN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_03_0 = {07 09 06 09 18 5a 18 6f ?? ?? ?? 0a 1f 10 28 ?? ?? ?? 0a d2 6f ?? ?? ?? 0a 00 00 09 17 58 0d 09 06 6f ?? ?? ?? 0a 18 5b } //1
		$a_01_1 = {47 65 74 54 79 70 65 } //1 GetType
		$a_01_2 = {43 00 72 00 65 00 61 00 74 00 65 00 49 00 6e 00 73 00 74 00 61 00 6e 00 63 00 65 00 } //1 CreateInstance
		$a_01_3 = {54 6f 49 6e 74 33 32 } //1 ToInt32
		$a_01_4 = {53 75 62 73 74 72 69 6e 67 } //1 Substring
		$a_01_5 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggableAttribute
		$a_01_6 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //1 DebuggingModes
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}