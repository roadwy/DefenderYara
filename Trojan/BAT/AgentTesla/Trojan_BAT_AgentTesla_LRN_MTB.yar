
rule Trojan_BAT_AgentTesla_LRN_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.LRN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_01_0 = {00 47 65 74 50 69 78 65 6c 00 } //1 䜀瑥楐數l
		$a_01_1 = {43 6f 6c 6f 72 54 72 61 6e 73 6c 61 74 6f 72 } //1 ColorTranslator
		$a_01_2 = {00 45 78 30 30 30 30 36 00 } //1
		$a_01_3 = {00 4c 65 76 65 6c 00 } //1
		$a_01_4 = {00 45 58 30 30 30 30 31 00 } //1
		$a_01_5 = {00 45 58 30 30 30 30 33 00 } //1
		$a_01_6 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggableAttribute
		$a_01_7 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerNonUserCodeAttribute
		$a_01_8 = {47 65 74 54 79 70 65 46 72 6f 6d 48 61 6e 64 6c 65 } //1 GetTypeFromHandle
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=9
 
}